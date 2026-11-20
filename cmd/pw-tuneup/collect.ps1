# pw-tuneup collector. READ-ONLY: looks, never changes anything. Prints one JSON object on stdout.
# Embedded in pw-tuneup.exe and handed to Windows PowerShell 5.1 on stdin. ASCII only on purpose (PS 5.1 misreads
# UTF-8 without a BOM). Every section is wrapped so one failure is recorded in "errors" and the rest still run.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false

$R = [ordered]@{ collector = 1; errors = @() }
function Section([string]$name, [scriptblock]$body) {
    try { $R[$name] = & $body }
    catch { $R.errors += ('{0}: {1}' -f $name, $_.Exception.Message) }
}
function MB($bytes) { if ($bytes) { [math]::Round($bytes / 1MB) } else { 0 } }
function DirMB([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return 0 }
    $s = (Get-ChildItem -LiteralPath $path -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    return (MB $s)
}
function WithTimeout([scriptblock]$sb, [int]$seconds) {
    $job = Start-Job -ScriptBlock $sb
    if (Wait-Job $job -Timeout $seconds) { $out = Receive-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force; return ,@($out) }
    Stop-Job $job; Remove-Job $job -Force; return $null
}
$Elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Section 'system' {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $plan = ''
    try { $m = [regex]::Match(((powercfg /getactivescheme) -join ' '), '\((.+)\)\s*\*?\s*$'); if ($m.Success) { $plan = $m.Groups[1].Value } } catch { }
    $arch = $env:PROCESSOR_ARCHITECTURE
    if ($env:PROCESSOR_ARCHITEW6432) { $arch = $env:PROCESSOR_ARCHITEW6432 }
    $chassis = @((Get-CimInstance Win32_SystemEnclosure).ChassisTypes)
    [ordered]@{
        host = $env:COMPUTERNAME
        model = ('{0} {1}' -f $cs.Manufacturer, $cs.Model).Trim()
        cpu = ([string]$cpu.Name).Trim()
        cores = [int]$cpu.NumberOfCores
        threads = [int]$cpu.NumberOfLogicalProcessors
        cpuLoad = [int]$cpu.LoadPercentage
        ramGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
        freeRamGB = [math]::Round($os.FreePhysicalMemory / 1MB, 1)
        os = [string]$os.Caption
        version = [string]$cv.DisplayVersion
        build = ('{0}.{1}' -f $os.BuildNumber, $cv.UBR)
        arch = $arch
        laptop = [bool]($chassis | Where-Object { $_ -in 8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32 })
        uptimeHours = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1)
        powerPlan = $plan
        elevated = $Elevated
        user = $env:USERNAME
    }
}

Section 'pendingReboot' {
    $why = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $why += 'component servicing' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $why += 'Windows Update' }
    try { if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction Stop).PendingFileRenameOperations) { $why += 'file replacements' } } catch { }
    ,@($why)
}

Section 'disks' {
    # Storage cmdlets need admin on some builds; the Win32_* classes below always work, so they are the fallback.
    $phys = @()
    try {
        $phys = @(Get-PhysicalDisk -ErrorAction Stop | ForEach-Object {
            $d = $_
            $rel = $null
            if ($Elevated) { try { $rel = $d | Get-StorageReliabilityCounter -ErrorAction Stop } catch { } }
            [ordered]@{
                id = [string]$d.DeviceId; name = [string]$d.FriendlyName; media = [string]$d.MediaType; bus = [string]$d.BusType
                sizeGB = [math]::Round($d.Size / 1GB); health = [string]$d.HealthStatus
                wear = if ($rel) { $rel.Wear } else { $null }
                tempC = if ($rel) { $rel.Temperature } else { $null }
                readErrors = if ($rel) { $rel.ReadErrorsUncorrected } else { $null }
            }
        })
    } catch {
        $phys = @(Get-CimInstance Win32_DiskDrive | ForEach-Object {
            [ordered]@{ id = [string]$_.Index; name = [string]$_.Model; media = ''; bus = [string]$_.InterfaceType
                        sizeGB = [math]::Round($_.Size / 1GB); health = if ($_.Status -eq 'OK') { 'Healthy' } else { [string]$_.Status }
                        wear = $null; tempC = $null; readErrors = $null }
        })
    }
    $sysDisk = $null
    try { $sysDisk = [string](Get-Partition -DriveLetter ($env:SystemDrive.Substring(0, 1)) -ErrorAction Stop | Select-Object -First 1).DiskNumber } catch { }
    $vols = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
        $letter = ([string]$_.DeviceID).Substring(0, 1)
        [ordered]@{
            letter = $letter; label = [string]$_.VolumeName; fs = [string]$_.FileSystem
            sizeGB = [math]::Round($_.Size / 1GB, 1); freeGB = [math]::Round($_.FreeSpace / 1GB, 1)
            windows = [bool](Test-Path -LiteralPath ('{0}:\Windows\System32\ntoskrnl.exe' -f $letter) -ErrorAction SilentlyContinue)
            system = (('{0}:' -f $letter) -eq $env:SystemDrive)
        }
    })
    [ordered]@{ physical = $phys; volumes = $vols; systemDisk = $sysDisk }
}

Section 'load' {
    $n = [Environment]::ProcessorCount
    $before = @{}
    foreach ($p in Get-Process) { if ($null -ne $p.CPU) { $before[$p.Id] = $p.CPU } }
    Start-Sleep -Seconds 4
    $rows = foreach ($p in Get-Process) {
        $cpuPct = 0
        if ($null -ne $p.CPU -and $before.ContainsKey($p.Id)) { $cpuPct = [math]::Round(($p.CPU - $before[$p.Id]) / 4 / $n * 100, 1) }
        [pscustomobject]@{ name = $p.ProcessName; cpu = $cpuPct; memMB = (MB $p.WorkingSet64) }
    }
    $byName = $rows | Group-Object name | ForEach-Object {
        [pscustomobject]@{ name = $_.Name; cpu = [math]::Round(($_.Group | Measure-Object cpu -Sum).Sum, 1); memMB = [int](($_.Group | Measure-Object memMB -Sum).Sum); count = $_.Count }
    }
    [ordered]@{
        sampleSeconds = 4
        topCpu = @($byName | Sort-Object cpu -Descending | Select-Object -First 8)
        topMem = @($byName | Sort-Object memMB -Descending | Select-Object -First 8)
        totalCpu = [math]::Round(($rows | Measure-Object cpu -Sum).Sum, 1)
        processes = @($rows).Count
    }
}

Section 'startup' {
    $approved = @{}
    $keys = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
    foreach ($k in $keys) {
        try {
            $item = Get-Item -LiteralPath $k -ErrorAction Stop
            foreach ($v in $item.GetValueNames()) { $b = $item.GetValue($v); if ($b -is [byte[]] -and $b.Length) { $approved[$v.ToLower()] = (($b[0] % 2) -eq 0) } }
        } catch { }
    }
    ,@(Get-CimInstance Win32_StartupCommand | ForEach-Object {
        $key = ([string]$_.Name).ToLower()
        $on = $true
        if ($approved.ContainsKey($key)) { $on = $approved[$key] } elseif ($approved.ContainsKey($key + '.lnk')) { $on = $approved[$key + '.lnk'] }
        [ordered]@{ name = [string]$_.Name; command = [string]$_.Command; location = [string]$_.Location; user = [string]$_.User; enabled = $on }
    })
}

Section 'drivers' {
    $skip = 'WAN Miniport|Virtual|Tailscale|Wintun|TAP-|Bluetooth|Kernel Debug|Hyper-V|VPN|Loopback|Wi-Fi Direct|Remote NDIS|Microsoft Basic|Npcap|Teredo|IP-HTTPS|6to4'
    $drv = @(Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DeviceClass -in 'DISPLAY', 'NET' -and $_.DeviceName -and $_.DeviceName -notmatch $skip } | ForEach-Object {
        $date = $null
        if ($_.DriverDate) { try { $date = ([datetime]$_.DriverDate).ToString('yyyy-MM-dd') } catch { } }
        [ordered]@{ name = [string]$_.DeviceName; class = [string]$_.DeviceClass; version = [string]$_.DriverVersion; date = $date; provider = [string]$_.DriverProviderName }
    })
    $problems = @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.ConfigManagerErrorCode -and $_.ConfigManagerErrorCode -ne 0 -and $_.ConfigManagerErrorCode -ne 22 } | ForEach-Object {
        [ordered]@{ name = [string]$_.Name; code = [int]$_.ConfigManagerErrorCode; class = [string]$_.PNPClass }
    })
    [ordered]@{ devices = $drv; problems = $problems }
}

Section 'updates' {
    $pending = WithTimeout {
        $s = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
        $res = $s.Search('IsInstalled=0 and IsHidden=0 and Type=''Software''')
        foreach ($u in $res.Updates) { $u.Title }
    } 120
    $last = $null
    try { $hf = Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1; if ($hf) { $last = $hf.InstalledOn.ToString('yyyy-MM-dd') } } catch { }
    $winget = $null
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        $wg = WithTimeout { winget upgrade --accept-source-agreements --disable-interactivity 2>$null } 60
        if ($null -ne $wg) {
            $m = [regex]::Match(($wg -join "`n"), '(\d+) upgrades? available')
            $winget = if ($m.Success) { [int]$m.Groups[1].Value } else { 0 }
        }
    }
    $titles = @()
    if ($null -ne $pending) { $titles = @($pending | Where-Object { $_ } | ForEach-Object { [string]$_ }) }
    [ordered]@{
        checked = ($null -ne $pending)
        pending = $titles
        lastInstalled = $last
        wingetUpgrades = $winget
    }
}

Section 'security' {
    $mp = $null
    try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { }
    $av = @()
    try { $av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object { [string]$_.displayName }) } catch { }
    $sb = $null
    try { $sb = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { if ($_.Exception.Message -match 'not supported') { $sb = 'unsupported' } }
    $tpm = $null
    if ($Elevated) { try { $t = Get-Tpm -ErrorAction Stop; $tpm = [ordered]@{ present = [bool]$t.TpmPresent; ready = [bool]$t.TpmReady } } catch { } }
    $bl = $null
    if ($Elevated) { try { $v = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop; $bl = [ordered]@{ protection = [string]$v.ProtectionStatus; status = [string]$v.VolumeStatus; percent = [int]$v.EncryptionPercentage } } catch { } }
    $fw = @()
    try { $fw = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { [ordered]@{ name = [string]$_.Name; enabled = [bool]$_.Enabled } }) } catch { }
    [ordered]@{
        antivirus = $av
        defender = if ($mp) { [ordered]@{
            service = [bool]$mp.AMServiceEnabled; realtime = [bool]$mp.RealTimeProtectionEnabled; tamper = [bool]$mp.IsTamperProtected
            signatureAgeDays = [int]$mp.AntivirusSignatureAge; quickScanAgeDays = [int]$mp.QuickScanAge
        } } else { $null }
        secureBoot = $sb
        tpm = $tpm
        bitlocker = $bl
        firewall = $fw
    }
}

Section 'recovery' {
    if (-not $Elevated) { return $null }
    $out = (reagentc /info) -join "`n"
    $m = [regex]::Match($out, 'Windows RE status:\s+(\w+)')
    [ordered]@{ status = if ($m.Success) { $m.Groups[1].Value } else { 'unknown' } }
}

Section 'network' {
    $wifi = $null
    $iface = (netsh wlan show interfaces) 2>$null
    if ($iface -and ($iface -join "`n") -match 'State\s+:\s+connected') {
        $get = { param($label) $l = $iface | Where-Object { $_ -match ('^\s+' + $label + '\s+:\s') } | Select-Object -First 1; if ($l) { ($l -split ':\s', 2)[1] } else { $null } }
        $wifi = [ordered]@{
            ssid = & $get 'SSID'; radio = & $get 'Radio type'; band = & $get 'Band'; channel = & $get 'Channel'
            signal = $($sig = & $get 'Signal'; if ($sig) { [int]($sig -replace '[^0-9]', '') } else { $null })
            rxMbps = & $get 'Receive rate \(Mbps\)'; auth = & $get 'Authentication'
        }
    }
    $profiles = @()
    $raw = (netsh wlan show profiles) 2>$null
    if ($raw) { $profiles = @($raw | Where-Object { $_ -match 'All User Profile\s+:\s' } | ForEach-Object { ($_ -split ':\s', 2)[1] }) }
    $conns = @()
    try { $conns = @(Get-NetConnectionProfile -ErrorAction Stop | ForEach-Object { [ordered]@{ alias = [string]$_.InterfaceAlias; name = [string]$_.Name; category = [string]$_.NetworkCategory; ipv4 = [string]$_.IPv4Connectivity } }) } catch { }
    $ts = $null
    $tsExe = @("$env:ProgramFiles\Tailscale\tailscale.exe", "${env:ProgramFiles(x86)}\Tailscale\tailscale.exe") | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if ($tsExe) {
        $ip = $null; try { $ip = ((& $tsExe ip -4) 2>$null | Select-Object -First 1) } catch { }
        $ts = [ordered]@{ installed = $true; ip = [string]$ip; up = [bool]$ip }
    }
    $sentinel = [bool](Get-Service -Name 'pwsentinel*', 'PWSentinel*' -ErrorAction SilentlyContinue) -or [bool](Get-ScheduledTask -TaskName 'PW Sentinel*' -ErrorAction SilentlyContinue)
    [ordered]@{ wifi = $wifi; wifiProfiles = $profiles; connections = $conns; tailscale = $ts; sentinel = $sentinel }
}

Section 'accounts' {
    $admins = @()
    try { $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { ($_.Name -split '\\')[-1] }) } catch { }
    ,@(Get-LocalUser -ErrorAction Stop | Where-Object Enabled | ForEach-Object {
        [ordered]@{
            name = [string]$_.Name; admin = ($admins -contains $_.Name)
            lastLogon = if ($_.LastLogon) { $_.LastLogon.ToString('yyyy-MM-dd') } else { $null }
            builtin = ($_.SID.Value -match '-(500|501|503|504)$')
        }
    })
}

Section 'battery' {
    # Laptops only. Win32_Battery gives charge, not wear; powercfg's XML battery report has design vs full capacity.
    $b = Get-CimInstance Win32_Battery | Select-Object -First 1
    if (-not $b) { return $null }
    # Unpredictable name (nothing can be planted there ahead of time); deleted again in finally.
    $x = Join-Path $env:TEMP ('pw-battery-{0}.xml' -f [guid]::NewGuid().ToString('N'))
    $design = $null; $full = $null; $cycles = $null
    try {
        & powercfg.exe /batteryreport /xml /output $x | Out-Null
        [xml]$doc = Get-Content -LiteralPath $x -Raw
        $bat = @($doc.BatteryReport.Batteries.Battery)[0]
        $design = [int]$bat.DesignCapacity; $full = [int]$bat.FullChargeCapacity; $cycles = [int]$bat.CycleCount
    } catch { } finally { Remove-Item -LiteralPath $x -Force -ErrorAction SilentlyContinue }
    [ordered]@{
        chargePct = [int]$b.EstimatedChargeRemaining
        designMWh = $design; fullMWh = $full; cycles = $cycles
        healthPct = if ($design -gt 0 -and $full -gt 0) { [math]::Round($full / $design * 100) } else { $null }
    }
}

Section 'junk' {
    $recycle = 0
    try { $sh = New-Object -ComObject Shell.Application; foreach ($i in $sh.NameSpace(10).Items()) { $recycle += $i.Size } } catch { }
    [ordered]@{
        userTempMB = DirMB $env:TEMP
        windowsTempMB = DirMB "$env:windir\Temp"
        updateCacheMB = DirMB "$env:windir\SoftwareDistribution\Download"
        crashDumpsMB = DirMB "$env:LOCALAPPDATA\CrashDumps"
        recycleBinMB = MB $recycle
        downloadsMB = DirMB (Join-Path $env:USERPROFILE 'Downloads')
    }
}

$R.collectedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$R | ConvertTo-Json -Depth 7 -Compress

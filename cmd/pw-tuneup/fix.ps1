# pw-tuneup fixer. Applies ONE named fix and prints one JSON line: {"ok":bool,"msg":"..."}.
# Only ever run after the person said yes to that fix. Each fix is limited to clearly safe, reversible or
# disposable things; anything that deletes user data, changes accounts or encryption is NOT here on purpose.
# -Arg is base64 of a UTF-8 JSON value (keeps Wi-Fi names with spaces and quotes intact). ASCII only (PS 5.1).
# pw-tuneup.exe hands this script to powershell.exe on stdin (never as a file in a user-writable folder).
param(
    [Parameter(Mandatory = $true)][string]$Fix,
    [string]$Arg = '',
    [string]$OutDir = $env:TEMP,
    [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false

function Done([bool]$ok, [string]$msg) { [ordered]@{ ok = $ok; msg = $msg } | ConvertTo-Json -Compress; exit 0 }
# ForEach-Object unrolls a JSON array: PS 5.1's ConvertFrom-Json emits the whole array as one object.
function ArgValue { if (-not $Arg) { return $null }; [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Arg)) | ConvertFrom-Json | ForEach-Object { $_ } }
function DirMB([string]$p) { if (-not (Test-Path -LiteralPath $p)) { return 0 }; [math]::Round(((Get-ChildItem -LiteralPath $p -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum) / 1MB) }
function IsReparse($item) { (([int]$item.Attributes) -band 0x400) -ne 0 }   # FileAttributes.ReparsePoint: junction, symlink, mount point

# ClearOld deletes files under $p last written more than $days ago, then the folders that are left empty.
# Walked by hand on purpose: Remove-Item -Recurse in Windows PowerShell 5.1 follows junctions, so a junction
# planted in a temp folder would let this (elevated) run delete whatever it points at. Reparse points are never
# entered and never deleted, at any level, and age is judged per file, not by the top folder's date.
# -TopOnly: files directly in $p only. For a folder every user can write to (C:\Windows\Temp): a standard user
# could swap a subfolder for a junction between the listing and the delete; the root itself they cannot swap.
function ClearOld([string]$p, [int]$days, [switch]$TopOnly) {
    $root = Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
    if (-not $root -or -not $root.PSIsContainer -or (IsReparse $root)) { return }
    $cut = (Get-Date).AddDays(-$days)
    $seen = New-Object System.Collections.ArrayList     # folders below the root, parents before children
    $todo = New-Object System.Collections.Stack
    $todo.Push($root)
    while ($todo.Count) {
        $d = $todo.Pop()
        $d.Refresh()
        if (-not $d.Exists -or (IsReparse $d)) { continue }   # swapped for a link since it was listed
        foreach ($i in @(Get-ChildItem -LiteralPath $d.FullName -Force -ErrorAction SilentlyContinue)) {
            if (IsReparse $i) { continue }
            if ($i.PSIsContainer) {
                if ($TopOnly) { continue }
                [void]$seen.Add([pscustomobject]@{ dir = $i; old = ($i.LastWriteTime -lt $cut) })   # date before its files go
                $todo.Push($i)
                continue
            }
            if ($i.LastWriteTime -ge $cut) { continue }
            try {
                if ($i.IsReadOnly) { $i.IsReadOnly = $false }
                $i.Delete()
            } catch { }   # in use or protected: skipped
        }
    }
    # Empty folders, deepest first; never the root. Directory.Delete without recursion only removes an empty folder.
    for ($k = $seen.Count - 1; $k -ge 0; $k--) {
        $d = $seen[$k].dir
        if (-not $seen[$k].old) { continue }
        $d.Refresh()
        if (-not $d.Exists -or (IsReparse $d)) { continue }
        if (@(Get-ChildItem -LiteralPath $d.FullName -Force -ErrorAction SilentlyContinue).Count) { continue }
        try { [IO.Directory]::Delete($d.FullName, $false) } catch { }
    }
}

# wlanapi.dll through an in-memory P/Invoke type (no Add-Type: that compiles through files in %TEMP%).
# WlanDeleteProfile matches the profile name exactly (case, spaces, quotes, '*'), which netsh does not.
function WlanApi {
    $asm = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object Reflection.AssemblyName 'PwTuneupWlan'), [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $tb = $asm.DefineDynamicModule('PwTuneupWlan').DefineType('PwTuneupWlan.Native', 'Public, Class')
    $sigs = @(
        @('WlanOpenHandle', [uint32], @([uint32], [IntPtr], [uint32].MakeByRefType(), [IntPtr].MakeByRefType())),
        @('WlanCloseHandle', [uint32], @([IntPtr], [IntPtr])),
        @('WlanEnumInterfaces', [uint32], @([IntPtr], [IntPtr], [IntPtr].MakeByRefType())),
        @('WlanDeleteProfile', [uint32], @([IntPtr], [Guid].MakeByRefType(), [string], [IntPtr])),
        @('WlanFreeMemory', [void], @(, [IntPtr]))
    )
    foreach ($s in $sigs) {
        $m = $tb.DefinePInvokeMethod($s[0], 'wlanapi.dll', 'Public, Static, PinvokeImpl', 'Standard', $s[1], [Type[]]$s[2], 'Winapi', 'Unicode')
        $m.SetImplementationFlags('PreserveSig')
    }
    $tb.CreateType()
}

# WlanInterfaces returns the GUIDs of the Wi-Fi adapters (WLAN_INTERFACE_INFO_LIST: two DWORDs, then 532-byte entries).
function WlanInterfaces($api, [IntPtr]$h) {
    $list = [IntPtr]::Zero
    $rc = $api::WlanEnumInterfaces($h, [IntPtr]::Zero, [ref]$list)
    if ($rc -ne 0) { throw ('WlanEnumInterfaces failed (error {0})' -f $rc) }
    try {
        $n = [Runtime.InteropServices.Marshal]::ReadInt32($list, 0)
        for ($i = 0; $i -lt $n; $i++) {
            $b = New-Object byte[] 16
            [Runtime.InteropServices.Marshal]::Copy([IntPtr]($list.ToInt64() + 8 + $i * 532), $b, 0, 16)
            New-Object Guid (, $b)
        }
    } finally { $api::WlanFreeMemory($list) }
}

try {
    switch ($Fix) {
        'restorepoint' {
            if ($DryRun) { Done $true 'would create a System Restore point' }
            try { Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction SilentlyContinue } catch { }
            $last = { @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue) | Sort-Object SequenceNumber | Select-Object -Last 1 }
            $before = & $last
            $w = $null
            Checkpoint-Computer -Description 'PW Tune-up' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop -WarningAction SilentlyContinue -WarningVariable w
            $after = & $last
            if ($after -and (-not $before -or $after.SequenceNumber -gt $before.SequenceNumber)) { Done $true 'restore point created' }
            # Windows makes at most one restore point a day and only warns when asked for another; a point that
            # recent still predates these fixes, anything older does not count.
            if ($after) {
                $t = [Management.ManagementDateTimeConverter]::ToDateTime($after.CreationTime)
                if ($t -gt (Get-Date).AddDays(-1)) { Done $true ("Windows makes one restore point a day; using the one from {0:yyyy-MM-dd HH:mm} ({1})" -f $t, $after.Description) }
            }
            Done $false ('no restore point was made' + $(if ($w) { ': ' + (($w | ForEach-Object { $_.Message }) -join ' ') } else { '' }))
        }
        'temp' {
            $dirs = @($env:TEMP, "$env:windir\Temp", "$env:LOCALAPPDATA\CrashDumps")
            $before = ($dirs | ForEach-Object { DirMB $_ } | Measure-Object -Sum).Sum
            if ($DryRun) { Done $true ("would clear files older than a day from user temp, Windows temp (its top folder only) and crash dumps ({0} MB now)" -f $before) }
            ClearOld $env:TEMP 1
            ClearOld "$env:windir\Temp" 1 -TopOnly   # writable by every user: see ClearOld
            ClearOld "$env:LOCALAPPDATA\CrashDumps" 1
            $after = ($dirs | ForEach-Object { DirMB $_ } | Measure-Object -Sum).Sum
            Done $true ("freed {0} MB (files in use and links were skipped)" -f [math]::Max(0, $before - $after))
        }
        'wucache' {
            $d = "$env:windir\SoftwareDistribution\Download"
            $before = DirMB $d
            if ($DryRun) { Done $true ("would stop Windows Update, clear its download cache ({0} MB) and start it again" -f $before) }
            Stop-Service -Name wuauserv, bits -Force -ErrorAction SilentlyContinue
            ClearOld $d 0
            Start-Service -Name bits, wuauserv -ErrorAction SilentlyContinue
            Done $true ("freed {0} MB; Windows Update restarted" -f [math]::Max(0, $before - (DirMB $d)))
        }
        'components' {
            if ($DryRun) { Done $true 'would run DISM component cleanup (removes superseded Windows update files)' }
            $out = & dism.exe /Online /Cleanup-Image /StartComponentCleanup /NoRestart 2>&1
            $ok = ($LASTEXITCODE -eq 0)
            Done $ok $(if ($ok) { 'component store cleaned' } else { 'DISM exit ' + $LASTEXITCODE + ': ' + (($out | Select-Object -Last 2) -join ' ') })
        }
        'netprivate' {
            $alias = [string](ArgValue)
            if (-not $alias) { Done $false 'no network given' }
            # -InterfaceAlias takes wildcards ("Wi-Fi*" would match every Wi-Fi adapter): pick the profile by its
            # exact adapter name and pipe that object in.
            $p = @(Get-NetConnectionProfile -ErrorAction Stop | Where-Object { $_.InterfaceAlias -ceq $alias })
            if (-not $p.Count) { Done $false ("no connection on an adapter named exactly '{0}'; nothing was changed" -f $alias) }
            if ($DryRun) { Done $true ("would mark the network on '{0}' as Private" -f $alias) }
            $p | Set-NetConnectionProfile -NetworkCategory Private -ErrorAction Stop
            Done $true ("'{0}' is now Private" -f $alias)
        }
        'winre' {
            if ($DryRun) { Done $true 'would enable Windows Recovery (reagentc /enable)' }
            $out = (& reagentc.exe /enable 2>&1) -join ' '
            $info = (& reagentc.exe /info 2>&1) -join "`n"
            if ($info -match 'Windows RE status:\s+Enabled') { Done $true 'Windows Recovery enabled' }
            Done $false ('still disabled; the recovery image is probably missing from this drive. reagentc said: ' + $out.Trim())
        }
        'wifidupes' {
            $names = @(ArgValue)
            if (-not $names.Count) { Done $false 'no profiles given' }
            foreach ($n in $names) {
                if ($n -isnot [string] -or $n.Length -eq 0 -or $n.Length -gt 255 -or $n -match '[\x00-\x1f\x7f]') { Done $false 'refusing an empty or unprintable profile name; nothing was changed' }
            }
            $bk = Join-Path $OutDir 'wifi-profile-backup'
            if ($DryRun) { Done $true ("would back up every Wi-Fi profile to {0} and delete: {1}" -f $bk, (($names | ForEach-Object { '"' + $_ + '"' }) -join ', ')) }
            $api = WlanApi
            $ver = [uint32]0; $h = [IntPtr]::Zero
            $rc = $api::WlanOpenHandle(2, [IntPtr]::Zero, [ref]$ver, [ref]$h)
            if ($rc -ne 0) { Done $false ('the WLAN service did not answer (error {0}); nothing was changed' -f $rc) }
            try {
                $ifs = @(WlanInterfaces $api $h)
                if (-not $ifs.Count) { Done $false 'no Wi-Fi adapter found; nothing was changed' }
                New-Item -ItemType Directory -Force -Path $bk | Out-Null
                & netsh.exe wlan export profile folder="$bk" | Out-Null     # keys stay encrypted to this PC (no key=clear)
                # Exact profile name -> its backup file, read from the XML (file names are sanitized by netsh).
                $files = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
                foreach ($x in @(Get-ChildItem -LiteralPath $bk -Filter '*.xml' -File -ErrorAction SilentlyContinue)) {
                    try { $doc = New-Object xml; $doc.Load($x.FullName); $pn = [string]$doc.WLANProfile.name; if ($pn -and -not $files.ContainsKey($pn)) { $files[$pn] = $x.FullName } } catch { }
                }
                $gone = @(); $skipped = @(); $restore = @()
                foreach ($n in $names) {
                    if (-not $files.ContainsKey($n)) { $skipped += ('"{0}" (no backup, kept)' -f $n); continue }
                    $hit = $false
                    foreach ($g in $ifs) { $gg = $g; if ($api::WlanDeleteProfile($h, [ref]$gg, $n, [IntPtr]::Zero) -eq 0) { $hit = $true } }
                    if ($hit) { $gone += $n; $restore += ('netsh wlan add profile filename="{0}"' -f $files[$n]) } else { $skipped += ('"{0}" (not found)' -f $n) }
                }
            } finally { [void]$api::WlanCloseHandle($h, [IntPtr]::Zero) }
            $msg = "deleted {0} of {1} duplicate profile(s); backups in {2}" -f $gone.Count, $names.Count, $bk
            if ($skipped.Count) { $msg += '; not deleted: ' + ($skipped -join ', ') }
            if ($restore.Count) { $msg += '. To put one back: ' + ($restore -join ' ; ') }
            Done ($gone.Count -eq $names.Count) $msg
        }
        'defender' {
            if ($DryRun) { Done $true 'would update Defender signatures and start a quick scan in the background' }
            Update-MpSignature -ErrorAction Stop
            $mp = "$env:ProgramFiles\Windows Defender\MpCmdRun.exe"
            if (Test-Path -LiteralPath $mp) { Start-Process -FilePath $mp -ArgumentList '-Scan', '-ScanType', '1' -WindowStyle Hidden }
            Done $true 'signatures updated; quick scan running in the background'
        }
        'firewall' {
            if ($DryRun) { Done $true 'would turn the Windows firewall on for every profile' }
            Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -ErrorAction Stop
            Done $true 'firewall on for Domain, Private and Public'
        }
        default { Done $false ('unknown fix: ' + $Fix) }
    }
} catch {
    Done $false $_.Exception.Message
}

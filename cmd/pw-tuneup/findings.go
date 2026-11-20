package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Severity, worst first.
const (
	SevBad  = "bad"
	SevWarn = "warn"
	SevInfo = "info"
	SevOK   = "ok"
)

var sevRank = map[string]int{SevBad: 0, SevWarn: 1, SevInfo: 2, SevOK: 3}

// Finding is one thing worth telling the person. Fix names a fix.ps1 action the tool can apply;
// Manual says what to do by hand when the tool will not (drivers, accounts, BIOS, encryption).
type Finding struct {
	ID       string `json:"id"`
	Area     string `json:"area"`
	Sev      string `json:"sev"`
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
	Manual   string `json:"manual,omitempty"`
	Fix      string `json:"fix,omitempty"`
	FixLabel string `json:"fixLabel,omitempty"`
	FixArg   any    `json:"fixArg,omitempty"`
	FixAdmin bool   `json:"fixAdmin,omitempty"`
	Confirm  string `json:"confirm,omitempty"` // asked on its own even under "apply all"
}

// Process names (lowercase, no .exe) that are known to churn in the background.
var knownHogs = map[string]string{
	"adobe desktop service": "Adobe Creative Cloud background service",
	"ccxprocess":            "Adobe Creative Cloud",
	"creative cloud":        "Adobe Creative Cloud",
	"adobeipcbroker":        "Adobe Creative Cloud",
	"msmpeng":               "Defender scanning (often scanning another app's writes)",
	"mpdefendercoreservice": "Defender",
	"tiworker":              "Windows Update installing",
	"trustedinstaller":      "Windows Update installing",
	"searchindexer":         "Windows Search indexing",
	"onedrive":              "OneDrive syncing",
	"steamwebhelper":        "Steam",
	"msedgewebview2":        "an app's embedded browser",
	"compattelrunner":       "Windows telemetry",
}

// Startup entries that are commonly worth turning off on a work machine.
var heavyStartup = []string{"onedrive", "steam", "epic", "adobe", "creative cloud", "teams", "discord", "spotify",
	"opera", "skype", "zoom", "dropbox", "google drive", "icloud", "ccleaner", "battle.net", "ea app", "origin", "ubisoft", "daemon tools"}

func analyze(r *Raw, now time.Time) []Finding {
	var f []Finding
	add := func(x Finding) { f = append(f, x) }

	if !r.collectedTime().IsZero() {
		now = r.collectedTime()
	}
	elevated := r.System != nil && r.System.Elevated

	// --- the basics ---------------------------------------------------------------------------
	if r.System != nil {
		s := r.System
		if !s.Elevated {
			add(Finding{ID: "not-admin", Area: "Tool", Sev: SevInfo, Title: "Ran without administrator rights",
				Detail: "Secure Boot, TPM, BitLocker, Windows Recovery and disk wear can only be read as administrator, and most fixes need it.",
				Manual: "Run pw-tuneup again and say Yes to the Windows prompt."})
		}
		if s.RAMGB > 0 && s.FreeRAMGB/s.RAMGB < 0.15 && r.Load != nil {
			add(Finding{ID: "ram-low", Area: "Performance", Sev: SevWarn,
				Title:  fmt.Sprintf("Memory is tight: %.1f GB free of %.0f GB", s.FreeRAMGB, s.RAMGB),
				Detail: "Biggest users: " + procList(r.Load.TopMem, 3, false)})
		}
		if s.UptimeHours > 24*14 {
			add(Finding{ID: "uptime", Area: "Performance", Sev: SevInfo,
				Title:  fmt.Sprintf("Not restarted in %d days", int(s.UptimeHours/24)),
				Manual: "Restart it once in a while; Windows finishes updates and frees leaked memory on restart."})
		}
		if strings.Contains(strings.ToLower(s.PowerPlan), "saver") && !s.Laptop {
			add(Finding{ID: "power-saver", Area: "Performance", Sev: SevInfo, Title: "Power plan is Power saver on a desktop",
				Manual: "Settings > System > Power > Power mode: Balanced or Best performance."})
		}
	}
	if len(r.PendingReboot) > 0 {
		sev := SevWarn // file replacements alone are left behind by app installers all the time
		if len(r.PendingReboot) == 1 && r.PendingReboot[0] == "file replacements" {
			sev = SevInfo
		}
		add(Finding{ID: "reboot-pending", Area: "Updates", Sev: sev, Title: "A restart is waiting",
			Detail: "Pending: " + strings.Join(r.PendingReboot, ", ") + ".", Manual: "Restart before judging speed; half-installed updates slow everything down."})
	}

	// --- background load ------------------------------------------------------------------------
	if r.Load != nil {
		var busy []string
		var why []string
		for _, p := range r.Load.TopCPU {
			if p.CPU < 8 {
				continue
			}
			busy = append(busy, fmt.Sprintf("%s %.0f%%", p.Name, p.CPU))
			if w, ok := knownHogs[strings.ToLower(p.Name)]; ok {
				why = append(why, w)
			}
		}
		if r.Load.TotalCPU >= 40 || len(busy) > 0 {
			sev := SevInfo
			if r.Load.TotalCPU >= 40 {
				sev = SevWarn
			}
			d := fmt.Sprintf("%.0f%% CPU in use with nothing asked of it.", r.Load.TotalCPU)
			if len(busy) > 0 {
				d += " Busiest: " + strings.Join(busy, ", ") + "."
			}
			if len(why) > 0 {
				d += " Likely cause: " + strings.Join(uniq(why), "; ") + "."
			}
			add(Finding{ID: "cpu-busy", Area: "Performance", Sev: sev, Title: "Busy in the background", Detail: d,
				Manual: "Let installers and first scans finish, or quit the app behind it. Sluggish with low CPU usually means the disk instead."})
		}
	}

	// --- disks ------------------------------------------------------------------------------------
	if r.Disks != nil {
		var winVols []string
		for _, v := range r.Disks.Volumes {
			if v.Windows {
				winVols = append(winVols, v.Letter+":")
			}
			if v.SizeGB <= 0 {
				continue
			}
			pct := v.FreeGB / v.SizeGB
			if pct < 0.10 || v.FreeGB < 15 {
				sev := SevWarn
				if pct < 0.05 || v.FreeGB < 5 {
					sev = SevBad
				}
				add(Finding{ID: "disk-full-" + strings.ToLower(v.Letter), Area: "Storage", Sev: sev,
					Title:  fmt.Sprintf("%s: is nearly full (%.0f GB free of %.0f GB)", v.Letter, v.FreeGB, v.SizeGB),
					Manual: "Settings > System > Storage > Cleanup recommendations, or move big folders off this drive."})
			}
		}
		if len(winVols) > 1 {
			add(Finding{ID: "multi-windows", Area: "Storage", Sev: SevWarn, Title: "Windows is installed on more than one drive (" + strings.Join(winVols, ", ") + ")",
				Detail: "The PC can boot the slower or older copy, and the second copy wastes space.",
				Manual: "Check the boot order in the BIOS, and once you are sure which copy you use, remove or wipe the other drive."})
		}
		for _, d := range r.Disks.Physical {
			label := strings.TrimSpace(d.Name)
			if d.Health != "" && !strings.EqualFold(d.Health, "Healthy") {
				add(Finding{ID: "disk-health-" + d.ID, Area: "Storage", Sev: SevBad, Title: label + " reports " + d.Health,
					Manual: "Back up now and plan to replace this drive."})
			}
			if d.Wear != nil && *d.Wear >= 80 {
				add(Finding{ID: "disk-wear-" + d.ID, Area: "Storage", Sev: SevWarn, Title: fmt.Sprintf("%s is %.0f%% worn", label, *d.Wear), Manual: "Plan to replace it."})
			}
			if d.TempC != nil && *d.TempC >= 65 {
				add(Finding{ID: "disk-temp-" + d.ID, Area: "Storage", Sev: SevWarn, Title: fmt.Sprintf("%s is running hot (%.0f C)", label, *d.TempC), Manual: "Check airflow or add a heatsink."})
			}
			if d.ReadErrors != nil && *d.ReadErrors > 0 {
				add(Finding{ID: "disk-errors-" + d.ID, Area: "Storage", Sev: SevWarn, Title: fmt.Sprintf("%s has %.0f uncorrected read errors", label, *d.ReadErrors), Manual: "Back up and run chkdsk; replace if the count grows."})
			}
			if d.ID == r.Disks.SystemDisk && strings.EqualFold(d.Media, "HDD") {
				add(Finding{ID: "hdd-system", Area: "Storage", Sev: SevWarn, Title: "Windows runs from a spinning hard drive (" + label + ")",
					Manual: "An SSD is the biggest single speed-up this PC can get."})
			}
		}
	}

	// --- startup ----------------------------------------------------------------------------------
	var on, heavy []string
	for _, s := range r.Startup {
		if !s.Enabled {
			continue
		}
		on = append(on, s.Name)
		ln := strings.ToLower(s.Name + " " + s.Command)
		for _, h := range heavyStartup {
			if strings.Contains(ln, h) {
				heavy = append(heavy, s.Name)
				break
			}
		}
	}
	if len(heavy) > 0 || len(on) > 10 {
		d := fmt.Sprintf("%d apps start with Windows.", len(on))
		if len(heavy) > 0 {
			d += " Worth a look: " + strings.Join(uniq(heavy), ", ") + "."
		}
		add(Finding{ID: "startup", Area: "Performance", Sev: SevInfo, Title: "Startup apps", Detail: d,
			Manual: "Settings > Apps > Startup: turn off anything you do not need the moment you log in."})
	}

	// --- drivers ----------------------------------------------------------------------------------
	if r.Drivers != nil {
		for _, d := range r.Drivers.Devices {
			t, err := time.Parse("2006-01-02", d.Date)
			if err != nil {
				continue
			}
			if age := now.Sub(t); age > 2*365*24*time.Hour {
				kind := "network"
				if d.Class == "DISPLAY" {
					kind = "graphics"
				}
				add(Finding{ID: "driver-" + slug(d.Name), Area: "Drivers", Sev: SevWarn,
					Title:  fmt.Sprintf("Old %s driver: %s", kind, d.Name),
					Detail: fmt.Sprintf("Version %s from %s (%d years old).", d.Version, d.Date, int(age.Hours()/24/365)),
					Manual: "Get the current driver from " + vendorHint(d) + ". Install it when nothing important is running; network drivers drop the connection for a moment."})
			}
		}
		if n := len(r.Drivers.Problems); n > 0 {
			var names []string
			for _, p := range r.Drivers.Problems {
				names = append(names, fmt.Sprintf("%s (code %d)", p.Name, p.Code))
			}
			add(Finding{ID: "problem-devices", Area: "Drivers", Sev: SevBad, Title: fmt.Sprintf("%d device(s) with a driver problem", n),
				Detail: strings.Join(names, "; "), Manual: "Device Manager: update or reinstall the driver for each one."})
		}
	}

	// --- updates ----------------------------------------------------------------------------------
	if r.Updates != nil {
		u := r.Updates
		var real []string
		for _, t := range u.Pending {
			if !strings.Contains(t, "Security Intelligence Update") {
				real = append(real, t)
			}
		}
		if !u.Checked {
			add(Finding{ID: "updates-unchecked", Area: "Updates", Sev: SevInfo, Title: "Windows Update did not answer within 2 minutes", Manual: "Open Settings > Windows Update and check by hand."})
		} else if len(real) > 0 {
			add(Finding{ID: "updates-pending", Area: "Updates", Sev: SevWarn, Title: fmt.Sprintf("%d Windows update(s) waiting", len(real)),
				Detail: strings.Join(first(real, 4), "; "), Manual: "Settings > Windows Update > Install all."})
		}
		if t, err := time.Parse("2006-01-02", u.LastInstalled); err == nil && now.Sub(t) > 45*24*time.Hour {
			add(Finding{ID: "updates-stale", Area: "Updates", Sev: SevWarn, Title: "No Windows update installed since " + u.LastInstalled,
				Manual: "Settings > Windows Update: check it is not paused and that updates install."})
		}
		if u.WingetUpgrades != nil && *u.WingetUpgrades > 0 {
			add(Finding{ID: "app-updates", Area: "Updates", Sev: SevInfo, Title: fmt.Sprintf("%d app update(s) available through winget", *u.WingetUpgrades),
				Manual: "In a terminal: winget upgrade (to see them), winget upgrade --all (to install)."})
		}
	}

	// --- security ---------------------------------------------------------------------------------
	if s := r.Security; s != nil {
		thirdParty := false
		for _, a := range s.Antivirus {
			if !strings.Contains(strings.ToLower(a), "defender") {
				thirdParty = true
			}
		}
		if d := s.Defender; d != nil && !thirdParty {
			if !d.Realtime {
				add(Finding{ID: "av-off", Area: "Security", Sev: SevBad, Title: "Real-time antivirus protection is off", Manual: "Windows Security > Virus & threat protection > Manage settings: turn Real-time protection on."})
			}
			if !d.Tamper {
				add(Finding{ID: "tamper-off", Area: "Security", Sev: SevWarn, Title: "Defender Tamper Protection is off",
					Manual: "Windows Security > Virus & threat protection > Manage settings > Tamper Protection: On. Windows only allows this by hand."})
			}
			if d.SignatureAgeDays > 3 || d.QuickScanAgeDays > 14 {
				add(Finding{ID: "av-stale", Area: "Security", Sev: SevWarn,
					Title: fmt.Sprintf("Defender is behind (signatures %d days old, last quick scan %d days ago)", d.SignatureAgeDays, d.QuickScanAgeDays),
					Fix:   "defender", FixLabel: "Update Defender and start a quick scan", FixAdmin: true})
			}
		}
		var off []string
		for _, w := range s.Firewall {
			if !w.Enabled {
				off = append(off, w.Name)
			}
		}
		if len(off) > 0 {
			add(Finding{ID: "firewall-off", Area: "Security", Sev: SevBad, Title: "Firewall is off for: " + strings.Join(off, ", "),
				Fix: "firewall", FixLabel: "Turn the firewall back on", FixAdmin: true})
		}
		switch strings.Trim(string(s.SecureBoot), `" `) {
		case "false":
			add(Finding{ID: "secureboot-off", Area: "Security", Sev: SevWarn, Title: "Secure Boot is off", Manual: "Turn it on in the BIOS/UEFI setup (Boot or Security tab)."})
		case "unsupported":
			add(Finding{ID: "secureboot-legacy", Area: "Security", Sev: SevInfo, Title: "PC boots in legacy BIOS mode (no Secure Boot)"})
		}
		if s.TPM != nil && (!s.TPM.Present || !s.TPM.Ready) {
			add(Finding{ID: "tpm", Area: "Security", Sev: SevInfo, Title: "TPM is missing or not ready", Manual: "Enable fTPM / PTT in the BIOS."})
		}
		if b := s.BitLocker; b != nil && strings.EqualFold(b.Protection, "Off") {
			add(Finding{ID: "bitlocker-off", Area: "Security", Sev: SevInfo, Title: "System drive is not encrypted",
				Manual: "Your call: turn on Device encryption/BitLocker and keep the recovery key somewhere you control. Before giving a PC away, make sure any old key is not tied to someone else's account."})
		}
	}
	if r.Recovery != nil && strings.EqualFold(r.Recovery.Status, "Disabled") {
		add(Finding{ID: "winre-off", Area: "Recovery", Sev: SevWarn, Title: "Windows Recovery is turned off",
			Detail: "Reset this PC and the startup repair menu fail without it.", Fix: "winre", FixLabel: "Turn Windows Recovery on", FixAdmin: true})
	}

	// --- network ----------------------------------------------------------------------------------
	if n := r.Network; n != nil {
		if w := n.Wifi; w != nil {
			if w.Signal != nil && *w.Signal < 50 {
				add(Finding{ID: "wifi-weak", Area: "Network", Sev: SevWarn, Title: fmt.Sprintf("Weak Wi-Fi signal on %s (%d%%)", w.SSID, *w.Signal),
					Manual: "Move closer to the access point, use Ethernet, or add a mesh node."})
			}
			if strings.Contains(w.Band, "2.4") || strings.Contains(w.Radio, "802.11n") {
				add(Finding{ID: "wifi-slow-band", Area: "Network", Sev: SevInfo, Title: fmt.Sprintf("Wi-Fi is on %s %s", w.Band, w.Radio),
					Manual: "If the router has 5 GHz or 6 GHz, connect to that band."})
			}
		}
		for _, c := range n.Connections {
			if strings.EqualFold(c.Category, "Public") && c.Alias != "" {
				add(Finding{ID: "net-public-" + slug(c.Alias), Area: "Network", Sev: SevWarn,
					Title:  fmt.Sprintf("Network \"%s\" on %s is marked Public", c.Name, c.Alias),
					Detail: "Public blocks discovery and file sharing, which breaks printers, casting and LAN tools on your own network.",
					Fix:    "netprivate", FixLabel: fmt.Sprintf("Mark \"%s\" as Private", c.Name), FixArg: c.Alias, FixAdmin: true,
					Confirm: fmt.Sprintf("Is \"%s\" your own network (home or shop), not public Wi-Fi?", c.Name)})
			}
		}
		if del := wifiDupes(n); len(del) > 0 {
			add(Finding{ID: "wifi-dupes", Area: "Network", Sev: SevWarn, Title: "Duplicate Wi-Fi profiles",
				Detail: "These differ only by spacing or capitals from another saved network, so Windows can join the wrong one: " + quoteAll(del) + ".",
				Fix:    "wifidupes", FixLabel: "Back up all Wi-Fi profiles and delete the duplicates", FixArg: del, FixAdmin: true})
		}
		if n.Tailscale == nil {
			add(Finding{ID: "vpn-missing", Area: "Fleet", Sev: SevInfo, Title: "Not on a Tailscale network (Tailscale not installed)"})
		} else if !n.Tailscale.Up {
			add(Finding{ID: "vpn-down", Area: "Fleet", Sev: SevWarn, Title: "Tailscale is installed but not connected", Manual: "Open Tailscale and log in."})
		}
		if !n.Sentinel {
			add(Finding{ID: "sentinel-missing", Area: "Fleet", Sev: SevInfo, Title: "Not enrolled in the PW Sentinel fleet monitor",
				Manual: "Install the PW Sentinel agent from your own fleet hub (see the PW Sentinel README)."})
		}
	}

	// --- accounts ---------------------------------------------------------------------------------
	current := ""
	if r.System != nil {
		current = strings.ToLower(r.System.User)
	}
	for _, a := range r.Accounts {
		if a.Builtin || strings.ToLower(a.Name) == current {
			continue
		}
		stale := a.LastLogon == ""
		if t, err := time.Parse("2006-01-02", a.LastLogon); err == nil && now.Sub(t) > 90*24*time.Hour {
			stale = true
		}
		if stale {
			last := "never signed in"
			if a.LastLogon != "" {
				last = "last signed in " + a.LastLogon
			}
			role := "standard"
			if a.Admin {
				role = "administrator"
			}
			add(Finding{ID: "account-" + slug(a.Name), Area: "Accounts", Sev: SevWarn, Title: fmt.Sprintf("Unused %s account \"%s\" (%s)", role, a.Name, last),
				Manual: "If nobody uses it, disable it: Computer Management > Local Users, or net user \"" + a.Name + "\" /active:no"})
		}
	}

	// --- junk -------------------------------------------------------------------------------------
	if j := r.Junk; j != nil {
		tmp := j.UserTempMB + j.WindowsTempMB + j.CrashDumpsMB
		if tmp >= 500 {
			add(Finding{ID: "junk-temp", Area: "Cleanup", Sev: SevInfo, Title: fmt.Sprintf("%s of temp files and crash dumps", size(tmp)),
				Fix: "temp", FixLabel: "Clear temp files and crash dumps older than a day", FixAdmin: j.WindowsTempMB > 0})
		}
		if j.UpdateCacheMB >= 500 {
			add(Finding{ID: "junk-wucache", Area: "Cleanup", Sev: SevInfo, Title: fmt.Sprintf("%s in the Windows Update download cache", size(j.UpdateCacheMB)),
				Fix: "wucache", FixLabel: "Clear the Windows Update download cache", FixAdmin: true})
		}
		if j.RecycleBinMB >= 1024 {
			add(Finding{ID: "junk-recycle", Area: "Cleanup", Sev: SevInfo, Title: fmt.Sprintf("%s in the Recycle Bin", size(j.RecycleBinMB)),
				Manual: "Empty it yourself once you are sure nothing in it is needed."})
		}
	}

	if b := r.Battery; b != nil && b.HealthPct != nil {
		h := *b.HealthPct
		cyc := ""
		if b.Cycles != nil && *b.Cycles > 0 {
			cyc = fmt.Sprintf(", %d charge cycles", *b.Cycles)
		}
		if h < 80 {
			sev := SevInfo
			if h < 70 {
				sev = SevWarn
			}
			add(Finding{ID: "battery-wear", Area: "Battery", Sev: sev, Title: fmt.Sprintf("Battery holds %d%% of its original charge%s", h, cyc),
				Manual: "Wear is normal with age; replace the battery if the runtime no longer gets you through the day."})
		}
	}
	if j := r.Junk; j != nil && j.DownloadsMB >= 5*1024 {
		add(Finding{ID: "downloads-big", Area: "Cleanup", Sev: SevInfo, Title: fmt.Sprintf("Downloads folder holds %s", size(j.DownloadsMB)),
			Manual: "Sort Downloads by size and delete installers and archives you no longer need."})
	}

	if len(r.Errors) > 0 {
		add(Finding{ID: "collector-errors", Area: "Tool", Sev: SevInfo, Title: "Some checks could not run", Detail: strings.Join(r.Errors, "; ")})
	}
	if !elevated {
		for i := range f {
			if f[i].FixAdmin {
				f[i].Detail = strings.TrimSpace(f[i].Detail + " (Fix needs administrator.)")
			}
		}
	}
	sort.SliceStable(f, func(i, j int) bool { return sevRank[f[i].Sev] < sevRank[f[j].Sev] })
	if worst(f) >= sevRank[SevInfo] {
		f = append([]Finding{{ID: "all-good", Area: "Summary", Sev: SevOK, Title: "Nothing needs attention"}}, f...)
	}
	return f
}

func score(f []Finding) int {
	s := 100
	for _, x := range f {
		switch x.Sev {
		case SevBad:
			s -= 15
		case SevWarn:
			s -= 5
		}
	}
	if s < 0 {
		return 0
	}
	return s
}

// verdict is the one-word reading of a score (same bands as the hand tune-up checklist).
func verdict(s int) string {
	switch {
	case s >= 90:
		return "Excellent"
	case s >= 75:
		return "Good"
	case s >= 60:
		return "Fair"
	}
	return "Needs attention"
}

func worst(f []Finding) int {
	w := sevRank[SevOK]
	for _, x := range f {
		if sevRank[x.Sev] < w {
			w = sevRank[x.Sev]
		}
	}
	return w
}

// wifiDupes returns the saved profile names to delete: in each group of names that are equal once
// spacing and case are ignored, keep the connected one (else the cleanly spelled one) and drop the rest.
func wifiDupes(n *Network) []string {
	groups := map[string][]string{}
	var order []string
	for _, p := range n.WifiProfiles {
		k := strings.ToLower(strings.Join(strings.Fields(p), " "))
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], p)
	}
	connected := ""
	if n.Wifi != nil {
		connected = n.Wifi.SSID
	}
	var del []string
	for _, k := range order {
		g := groups[k]
		if len(g) < 2 {
			continue
		}
		keep := -1
		for i, p := range g {
			if p == connected {
				keep = i
			}
		}
		if keep < 0 {
			for i, p := range g {
				if p == strings.TrimSpace(p) {
					keep = i
					break
				}
			}
		}
		if keep < 0 {
			keep = 0
		}
		for i, p := range g {
			if i != keep {
				del = append(del, p)
			}
		}
	}
	return del
}

func (r *Raw) collectedTime() time.Time {
	t, _ := time.Parse(time.RFC3339, r.CollectedAt)
	return t
}

func procList(p []Proc, n int, cpu bool) string {
	var out []string
	for i, x := range p {
		if i >= n {
			break
		}
		if cpu {
			out = append(out, fmt.Sprintf("%s %.0f%%", x.Name, x.CPU))
		} else {
			out = append(out, fmt.Sprintf("%s %s", x.Name, size(x.MemMB)))
		}
	}
	return strings.Join(out, ", ")
}

func vendorHint(d Driver) string {
	n := strings.ToLower(d.Name + " " + d.Provider)
	switch {
	case strings.Contains(n, "nvidia"):
		return "nvidia.com/drivers (or the NVIDIA app)"
	case strings.Contains(n, "amd") || strings.Contains(n, "radeon"):
		return "amd.com/support"
	case strings.Contains(n, "intel"):
		return "Intel's Driver & Support Assistant (11th-14th gen graphics are on Intel's separate legacy page)"
	case strings.Contains(n, "realtek"):
		return "the PC or motherboard maker's support page"
	}
	return "the PC or motherboard maker's support page"
}

func size(mb float64) string {
	if mb >= 1024 {
		return fmt.Sprintf("%.1f GB", mb/1024)
	}
	return fmt.Sprintf("%.0f MB", mb)
}

func slug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else if b.Len() > 0 && !strings.HasSuffix(b.String(), "-") {
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func uniq(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range s {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func first(s []string, n int) []string {
	if len(s) > n {
		return append(append([]string{}, s[:n]...), fmt.Sprintf("and %d more", len(s)-n))
	}
	return s
}

func quoteAll(s []string) string {
	var out []string
	for _, x := range s {
		out = append(out, `"`+x+`"`)
	}
	return strings.Join(out, ", ")
}

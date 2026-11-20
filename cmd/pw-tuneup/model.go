package main

import (
	"bytes"
	"encoding/json"
)

// list accepts a JSON array OR a single value: Windows PowerShell 5.1 collapses one-item arrays.
type list[T any] []T

func (l *list[T]) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*l = nil
		return nil
	}
	if b[0] == '[' {
		var v []T
		err := json.Unmarshal(b, &v)
		*l = v
		return err
	}
	var one T
	if err := json.Unmarshal(b, &one); err != nil {
		return err
	}
	*l = list[T]{one}
	return nil
}

// Raw is what collect.ps1 prints. Every section may be missing (it failed, or needs admin).
type Raw struct {
	Errors        list[string]      `json:"errors"`
	CollectedAt   string            `json:"collectedAt"`
	System        *System           `json:"system"`
	PendingReboot list[string]      `json:"pendingReboot"`
	Disks         *Disks            `json:"disks"`
	Load          *Load             `json:"load"`
	Startup       list[StartupItem] `json:"startup"`
	Drivers       *Drivers          `json:"drivers"`
	Updates       *Updates          `json:"updates"`
	Security      *Security         `json:"security"`
	Recovery      *Recovery         `json:"recovery"`
	Network       *Network          `json:"network"`
	Accounts      list[Account]     `json:"accounts"`
	Junk          *Junk             `json:"junk"`
	Battery       *Battery          `json:"battery"`
}

type Battery struct {
	ChargePct int  `json:"chargePct"`
	DesignMWh *int `json:"designMWh"`
	FullMWh   *int `json:"fullMWh"`
	Cycles    *int `json:"cycles"`
	HealthPct *int `json:"healthPct"`
}

type System struct {
	Host        string  `json:"host"`
	Model       string  `json:"model"`
	CPU         string  `json:"cpu"`
	Cores       int     `json:"cores"`
	Threads     int     `json:"threads"`
	CPULoad     int     `json:"cpuLoad"`
	RAMGB       float64 `json:"ramGB"`
	FreeRAMGB   float64 `json:"freeRamGB"`
	OS          string  `json:"os"`
	Version     string  `json:"version"`
	Build       string  `json:"build"`
	Arch        string  `json:"arch"`
	Laptop      bool    `json:"laptop"`
	UptimeHours float64 `json:"uptimeHours"`
	PowerPlan   string  `json:"powerPlan"`
	Elevated    bool    `json:"elevated"`
	User        string  `json:"user"`
}

type Disks struct {
	Physical   list[PhysicalDisk] `json:"physical"`
	Volumes    list[Volume]       `json:"volumes"`
	SystemDisk string             `json:"systemDisk"`
}

type PhysicalDisk struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Media      string   `json:"media"`
	Bus        string   `json:"bus"`
	SizeGB     float64  `json:"sizeGB"`
	Health     string   `json:"health"`
	Wear       *float64 `json:"wear"`
	TempC      *float64 `json:"tempC"`
	ReadErrors *float64 `json:"readErrors"`
}

type Volume struct {
	Letter  string  `json:"letter"`
	Label   string  `json:"label"`
	FS      string  `json:"fs"`
	SizeGB  float64 `json:"sizeGB"`
	FreeGB  float64 `json:"freeGB"`
	Windows bool    `json:"windows"`
	System  bool    `json:"system"`
}

type Proc struct {
	Name  string  `json:"name"`
	CPU   float64 `json:"cpu"`
	MemMB float64 `json:"memMB"`
	Count int     `json:"count"`
}

type Load struct {
	SampleSeconds int        `json:"sampleSeconds"`
	TopCPU        list[Proc] `json:"topCpu"`
	TopMem        list[Proc] `json:"topMem"`
	TotalCPU      float64    `json:"totalCpu"`
	Processes     int        `json:"processes"`
}

type StartupItem struct {
	Name     string `json:"name"`
	Command  string `json:"command"`
	Location string `json:"location"`
	User     string `json:"user"`
	Enabled  bool   `json:"enabled"`
}

type Driver struct {
	Name     string `json:"name"`
	Class    string `json:"class"`
	Version  string `json:"version"`
	Date     string `json:"date"`
	Provider string `json:"provider"`
}

type ProblemDevice struct {
	Name  string `json:"name"`
	Code  int    `json:"code"`
	Class string `json:"class"`
}

type Drivers struct {
	Devices  list[Driver]        `json:"devices"`
	Problems list[ProblemDevice] `json:"problems"`
}

type Updates struct {
	Checked        bool         `json:"checked"`
	Pending        list[string] `json:"pending"`
	LastInstalled  string       `json:"lastInstalled"`
	WingetUpgrades *int         `json:"wingetUpgrades"`
}

type Defender struct {
	Service          bool `json:"service"`
	Realtime         bool `json:"realtime"`
	Tamper           bool `json:"tamper"`
	SignatureAgeDays int  `json:"signatureAgeDays"`
	QuickScanAgeDays int  `json:"quickScanAgeDays"`
}

type Firewall struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

type Security struct {
	Antivirus  list[string]    `json:"antivirus"`
	Defender   *Defender       `json:"defender"`
	SecureBoot json.RawMessage `json:"secureBoot"` // true | false | "unsupported" | null (needs admin)
	TPM        *struct {
		Present bool `json:"present"`
		Ready   bool `json:"ready"`
	} `json:"tpm"`
	BitLocker *struct {
		Protection string `json:"protection"`
		Status     string `json:"status"`
		Percent    int    `json:"percent"`
	} `json:"bitlocker"`
	Firewall list[Firewall] `json:"firewall"`
}

type Recovery struct {
	Status string `json:"status"`
}

type Wifi struct {
	SSID    string `json:"ssid"`
	Radio   string `json:"radio"`
	Band    string `json:"band"`
	Channel string `json:"channel"`
	Signal  *int   `json:"signal"`
	RxMbps  string `json:"rxMbps"`
	Auth    string `json:"auth"`
}

type Connection struct {
	Alias    string `json:"alias"`
	Name     string `json:"name"`
	Category string `json:"category"`
	IPv4     string `json:"ipv4"`
}

type Network struct {
	Wifi         *Wifi            `json:"wifi"`
	WifiProfiles list[string]     `json:"wifiProfiles"`
	Connections  list[Connection] `json:"connections"`
	Tailscale    *struct {
		Installed bool   `json:"installed"`
		IP        string `json:"ip"`
		Up        bool   `json:"up"`
	} `json:"tailscale"`
	Sentinel bool `json:"sentinel"`
}

type Account struct {
	Name      string `json:"name"`
	Admin     bool   `json:"admin"`
	LastLogon string `json:"lastLogon"`
	Builtin   bool   `json:"builtin"`
}

type Junk struct {
	UserTempMB    float64 `json:"userTempMB"`
	WindowsTempMB float64 `json:"windowsTempMB"`
	UpdateCacheMB float64 `json:"updateCacheMB"`
	CrashDumpsMB  float64 `json:"crashDumpsMB"`
	RecycleBinMB  float64 `json:"recycleBinMB"`
	DownloadsMB   float64 `json:"downloadsMB"`
}

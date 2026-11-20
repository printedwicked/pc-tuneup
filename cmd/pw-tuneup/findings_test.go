package main

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func load(t *testing.T, name string) (*Raw, []byte) {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var r Raw
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return &r, b
}

func byID(f []Finding) map[string]Finding {
	m := map[string]Finding{}
	for _, x := range f {
		m[x.ID] = x
	}
	return m
}

// The messy PC is invented (Contoso/Fabrikam parts, made-up networks and accounts) and carries every
// problem the hand tune-ups found.
func TestMessyPC(t *testing.T) {
	r, _ := load(t, "messy-pc.json")
	f := analyze(r, time.Now())
	m := byID(f)
	for _, id := range []string{
		"ram-low", "uptime", "reboot-pending", "cpu-busy", "multi-windows", "hdd-system", "startup",
		"driver-contoso-graphics-600", "problem-devices", "updates-pending", "updates-stale", "app-updates",
		"tamper-off", "av-stale", "firewall-off", "secureboot-off", "bitlocker-off", "winre-off",
		"wifi-weak", "net-public-wi-fi", "wifi-dupes", "vpn-down", "sentinel-missing", "account-kiosk",
		"junk-temp", "junk-wucache", "junk-recycle", "battery-wear", "downloads-big",
	} {
		if _, ok := m[id]; !ok {
			t.Errorf("missing finding %q", id)
		}
	}
	for _, id := range []string{"account-robin", "account-administrator", "driver-fabrikam-wireless-ax3000", "all-good", "not-admin"} {
		if _, ok := m[id]; ok {
			t.Errorf("unexpected finding %q", id)
		}
	}
	if got := m["cpu-busy"].Detail; !strings.Contains(got, "Adobe") || !strings.Contains(got, "Defender") {
		t.Errorf("cpu-busy should name Adobe and Defender: %s", got)
	}
	if got := m["updates-pending"].Title; !strings.HasPrefix(got, "1 ") {
		t.Errorf("Defender intelligence updates should not count as Windows updates: %s", got)
	}
	// keep the connected network and the cleanly spelled one; delete the trailing-space and lower-case twins
	if got, want := m["wifi-dupes"].FixArg, []string{"Harbor View ", "workshop"}; !reflect.DeepEqual(got, want) {
		t.Errorf("wifi dupes = %#v, want %#v", got, want)
	}
	if m["net-public-wi-fi"].Confirm == "" || m["net-public-wi-fi"].FixArg != "Wi-Fi" {
		t.Errorf("public network fix must ask first and target the adapter: %+v", m["net-public-wi-fi"])
	}
	if f[0].Sev != SevBad {
		t.Errorf("worst findings should come first, got %s", f[0].Sev)
	}
	if s := score(f); s != 0 || verdict(s) != "Needs attention" {
		t.Errorf("score = %d (%s), want 0 for this PC", s, verdict(s))
	}
	if m["battery-wear"].Sev != SevWarn {
		t.Errorf("65%% battery should warn")
	}
}

func TestCleanPC(t *testing.T) {
	r := &Raw{
		CollectedAt: "2026-11-07T12:00:00Z",
		System:      &System{Host: "OK", RAMGB: 32, FreeRAMGB: 20, UptimeHours: 5, Elevated: true, User: "user"},
		Load:        &Load{TotalCPU: 3},
		Updates:     &Updates{Checked: true, LastInstalled: "2026-11-01"},
		Network:     &Network{Sentinel: true},
	}
	r.Network.Tailscale = &struct {
		Installed bool   `json:"installed"`
		IP        string `json:"ip"`
		Up        bool   `json:"up"`
	}{true, "10.0.0.10", true}
	f := analyze(r, time.Now())
	if len(f) != 1 || f[0].ID != "all-good" || score(f) != 100 {
		t.Errorf("clean PC should be all-good at 100, got %+v", f)
	}
}

// One-item arrays come back from PowerShell 5.1 as bare values.
func TestListAcceptsSingleValue(t *testing.T) {
	var v struct {
		A list[string] `json:"a"`
		B list[string] `json:"b"`
		C list[string] `json:"c"`
	}
	if err := json.Unmarshal([]byte(`{"a":"x","b":["x","y"],"c":null}`), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.A) != 1 || len(v.B) != 2 || v.C != nil {
		t.Errorf("got %+v", v)
	}
}

func TestReportRenders(t *testing.T) {
	r, b := load(t, "messy-pc.json")
	f := analyze(r, time.Now())
	dir := t.TempDir()
	p, err := writeReport(dir, r, b, f, []FixResult{{Label: "Clear temp", OK: true, Msg: "freed 1.2 GB"}})
	if err != nil {
		t.Fatal(err)
	}
	h, _ := os.ReadFile(p)
	for _, want := range []string{"DEMO-TOWER", "Duplicate Wi-Fi profiles", "freed 1.2 GB", "Fabrikam HD1000 7200"} {
		if !strings.Contains(string(h), want) {
			t.Errorf("report missing %q", want)
		}
	}
}

// PW_TUNEUP_MOCK=<folder> go test -run TestRenderMock ./... writes the fixture's report there; docs/report-mock.png
// is a headless-browser screenshot of it.
func TestRenderMock(t *testing.T) {
	dir := os.Getenv("PW_TUNEUP_MOCK")
	if dir == "" {
		t.Skip("set PW_TUNEUP_MOCK to a folder to render the mock report")
	}
	r, b := load(t, "messy-pc.json")
	p, err := writeReport(dir, r, b, analyze(r, time.Now()), []FixResult{
		{Label: "Restore point", OK: true, Msg: "restore point created"},
		{Label: "Clear temp files and crash dumps older than a day", OK: true, Msg: "freed 1712 MB (files in use and links were skipped)"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(p)
}

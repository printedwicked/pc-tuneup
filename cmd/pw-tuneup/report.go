package main

import (
	_ "embed"
	"encoding/json"
	"html/template"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var hkuSID = regexp.MustCompile(`^HKU\\S-[0-9-]+\\`)

// shortLocation turns HKU\S-1-5-21-...\SOFTWARE\Microsoft\Windows\CurrentVersion\Run into HKCU ... Run.
func shortLocation(s string) string {
	s = hkuSID.ReplaceAllString(s, `HKCU\`)
	return strings.Replace(s, `SOFTWARE\Microsoft\Windows\CurrentVersion\`, `...\`, 1)
}

//go:embed report.html
var reportHTML string

// FixResult is what one applied (or dry-run) fix reported back.
type FixResult struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	OK    bool   `json:"ok"`
	Dry   bool   `json:"dry,omitempty"`
	Msg   string `json:"msg"`
}

type reportData struct {
	Version    string
	When       string
	Sys        System
	Score      int
	ScoreClass string
	Verdict    string
	Count      map[string]int
	Findings   []Finding
	Results    []FixResult
	Raw        *Raw
	RawJSON    string
}

// writeReport saves report.html and report.json into dir and returns the html path.
func writeReport(dir string, raw *Raw, rawJSON []byte, f []Finding, res []FixResult) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	safe := *raw // the template walks these; give it empty sections instead of nil pointers
	if safe.System == nil {
		safe.System = &System{Host: "this PC"}
	}
	if safe.Disks == nil {
		safe.Disks = &Disks{}
	}
	if safe.Load == nil {
		safe.Load = &Load{}
	}
	if safe.Drivers == nil {
		safe.Drivers = &Drivers{}
	}
	d := reportData{
		Version: Version, When: time.Now().Format("2006-01-02 15:04"), Sys: *safe.System,
		Score: score(f), Count: map[string]int{SevBad: 0, SevWarn: 0, SevInfo: 0}, Findings: f, Results: res, Raw: &safe,
	}
	for _, x := range f {
		d.Count[x.Sev]++
	}
	d.Verdict = verdict(d.Score)
	switch {
	case d.Score >= 85:
		d.ScoreClass = "good"
	case d.Score >= 60:
		d.ScoreClass = "mid"
	default:
		d.ScoreClass = "low"
	}
	pretty, _ := json.MarshalIndent(json.RawMessage(rawJSON), "", "  ")
	d.RawJSON = string(pretty)

	t, err := template.New("r").Funcs(template.FuncMap{
		"deref":  func(p *float64) float64 { return *p },
		"derefi": func(p *int) int { return *p },
		"loc":    shortLocation,
	}).Parse(reportHTML)
	if err != nil {
		return "", err
	}
	htmlPath := filepath.Join(dir, "report.html")
	out, err := os.Create(htmlPath)
	if err != nil {
		return "", err
	}
	defer out.Close()
	if err := t.Execute(out, d); err != nil {
		return "", err
	}
	js, _ := json.MarshalIndent(map[string]any{
		"version": Version, "score": d.Score, "findings": f, "fixes": res, "collected": json.RawMessage(rawJSON),
	}, "", "  ")
	return htmlPath, os.WriteFile(filepath.Join(dir, "report.json"), js, 0o644)
}

package main

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode/utf16"
)

//go:embed collect.ps1
var collectPS1 []byte

//go:embed fix.ps1
var fixPS1 []byte

// The scripts never touch the disk: a writable copy in %TEMP% could be swapped between writing it and the
// elevated powershell.exe reading it. powershell.exe gets a short -EncodedCommand bootstrap that reads the
// script (base64, so no console code page can mangle it) from stdin and runs it with the parameters baked in.
// The scripts themselves are too big for -EncodedCommand (the command line tops out near 32K characters).
const bootstrap = `$ErrorActionPreference = 'Stop'; ` +
	`$s = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd().Trim())); ` +
	`& ([scriptblock]::Create($s))`

func powershell() string {
	if root := os.Getenv("SystemRoot"); root != "" {
		p := filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "powershell.exe"
}

// psString is a PowerShell expression for s that survives any quote characters in it
// (PowerShell also treats the typographic single quotes as quotes).
func psString(s string) string {
	return "([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + base64.StdEncoding.EncodeToString([]byte(s)) + "')))"
}

// encodeCommand is what -EncodedCommand expects: base64 of the UTF-16LE text.
func encodeCommand(s string) string {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// runScript runs one embedded script; params is PowerShell parameter text appended to the bootstrap.
func runScript(name string, body []byte, params string) ([]byte, error) {
	cmd := exec.Command(powershell(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", encodeCommand(bootstrap+params))
	cmd.Stdin = strings.NewReader(base64.StdEncoding.EncodeToString(body))
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if err != nil && out.Len() == 0 {
		return nil, fmt.Errorf("%s: %v %s", name, err, strings.TrimSpace(errb.String()))
	}
	return bytes.TrimSpace(out.Bytes()), nil
}

// collect runs the read-only collector and parses it.
func collect() (*Raw, []byte, error) {
	out, err := runScript("collect.ps1", collectPS1, "")
	if err != nil {
		return nil, nil, err
	}
	// The JSON is the last line; anything a module printed before it is ignored.
	if i := bytes.LastIndexByte(out, '\n'); i >= 0 {
		out = bytes.TrimSpace(out[i+1:])
	}
	var r Raw
	if err := json.Unmarshal(out, &r); err != nil {
		return nil, out, fmt.Errorf("collector output: %v", err)
	}
	return &r, out, nil
}

// fix runs one fix.ps1 action.
func fix(name string, arg any, outDir string, dry bool) FixResult {
	params := " -Fix " + psString(name) + " -OutDir " + psString(outDir)
	if arg != nil {
		b, _ := json.Marshal(arg)
		params += " -Arg '" + base64.StdEncoding.EncodeToString(b) + "'"
	}
	if dry {
		params += " -DryRun"
	}
	out, err := runScript("fix.ps1", fixPS1, params)
	if err != nil {
		return FixResult{ID: name, OK: false, Msg: err.Error()}
	}
	if i := bytes.LastIndexByte(out, '\n'); i >= 0 {
		out = bytes.TrimSpace(out[i+1:])
	}
	var r struct {
		OK  bool   `json:"ok"`
		Msg string `json:"msg"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		return FixResult{ID: name, OK: false, Msg: "unreadable result: " + string(out)}
	}
	return FixResult{ID: name, OK: r.OK, Msg: r.Msg}
}

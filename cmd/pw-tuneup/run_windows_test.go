//go:build windows

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// The bootstrap carries scripts bigger than a command line and parameters with any quotes in them.
func TestRunScriptStdin(t *testing.T) {
	body := "param($A, $B) [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false; Write-Output ('got:' + $A + '|' + $B)\n#" + strings.Repeat("x", 40000) + "\n"
	a, b := `it's "quoted" ‘typographic’ $(nope) *`, `C:\Some Folder\x`
	out, err := runScript("test", []byte(body), " -A "+psString(a)+" -B "+psString(b))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(out), "got:"+a+"|"+b; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// Dry runs change nothing; they check the fix.ps1 plumbing end to end.
func TestFixDryRuns(t *testing.T) {
	dir := filepath.Join(t.TempDir(), `it's ‘here’`)
	if r := fix("restorepoint", nil, dir, true); !r.OK || !strings.HasPrefix(r.Msg, "would create") {
		t.Errorf("restorepoint: %+v", r)
	}
	if r := fix("wifidupes", []string{`Harbor "View" `, "*"}, dir, true); !r.OK || !strings.Contains(r.Msg, `"Harbor "View" ", "*"`) ||
		!strings.Contains(r.Msg, dir) {
		t.Errorf("wifidupes: %+v", r)
	}
	if r := fix("wifidupes", []string{"bad\tname"}, dir, true); r.OK || !strings.Contains(r.Msg, "refusing") {
		t.Errorf("wifidupes must refuse control characters: %+v", r)
	}
	// A wildcard alias must not match a real adapter (Set-NetConnectionProfile -InterfaceAlias would).
	if r := fix("netprivate", "*", dir, true); r.OK {
		t.Errorf("netprivate matched a wildcard: %+v", r)
	}
	if r := fix("nosuchfix", nil, dir, true); r.OK || !strings.Contains(r.Msg, "unknown fix") {
		t.Errorf("unknown fix: %+v", r)
	}
}

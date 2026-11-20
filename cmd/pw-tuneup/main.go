// pw-tuneup checks a Windows PC the way a careful hand tune-up does,
// writes an HTML report, and applies only the fixes the person says yes to.
//
//	pw-tuneup                 double-click: asks for admin, checks, offers fixes, opens the report
//	pw-tuneup --report-only   check and report, change nothing
//	pw-tuneup --yes           apply every safe fix without asking (network changes are still asked)
//	pw-tuneup --dry-run       show what each fix would do, change nothing
//	pw-tuneup --deep          also offer DISM component cleanup (slow)
//	pw-tuneup --no-restore-point  apply fixes even if no restore point could be made (otherwise it asks)
//	pw-tuneup --json          print findings + raw data as JSON (for scripts / Sentinel), change nothing
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const Version = "1.0.1"

func main() {
	args := os.Args[1:]
	fs := flag.NewFlagSet("pw-tuneup", flag.ContinueOnError)
	reportOnly := fs.Bool("report-only", false, "check and report, change nothing")
	yes := fs.Bool("yes", false, "apply every safe fix without asking (network changes are still asked)")
	dry := fs.Bool("dry-run", false, "show what each fix would do, change nothing")
	deep := fs.Bool("deep", false, "also offer DISM component cleanup (takes several minutes)")
	outFlag := fs.String("out", "", "folder for the report (default Documents\\PW Tune-up\\<PC>-<time>)")
	noOpen := fs.Bool("no-open", false, "do not open the report when done")
	jsonOut := fs.Bool("json", false, "print findings and raw data as JSON; changes nothing")
	noAdmin := fs.Bool("no-admin", false, "do not ask for administrator rights")
	showVer := fs.Bool("version", false, "print the version")
	pauseFlag := fs.Bool("pause", false, "wait for Enter before closing")
	noRestore := fs.Bool("no-restore-point", false, "apply fixes even when no restore point could be made (otherwise it asks, or stops when it cannot ask)")
	elevatedTry := fs.Bool("elevated", false, "internal: this copy was started through UAC")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	pause := len(args) == 0 || *pauseFlag
	exit := func(code int) {
		if pause {
			fmt.Print("\nPress Enter to close...")
			bufio.NewReader(os.Stdin).ReadString('\n')
		}
		os.Exit(code)
	}
	if *showVer {
		fmt.Println("pw-tuneup", Version)
		return
	}
	if *jsonOut {
		*reportOnly, *noOpen, *noAdmin = true, true, true
	}

	if !*noAdmin && !isAdmin() && !*elevatedTry {
		fmt.Println("PW Tune-up " + Version + ": asking Windows for administrator rights (say Yes for the full check and the fixes)...")
		a := append(append([]string{}, args...), "--elevated")
		if pause && !*pauseFlag {
			a = append(a, "--pause")
		}
		if err := relaunchElevated(a); err == nil {
			return // the elevated copy carries on in its own window
		}
		fmt.Println("Continuing without administrator rights; some checks and fixes will be skipped.")
	}
	admin := isAdmin()

	if !*jsonOut {
		fmt.Printf("PW Tune-up %s\nChecking this PC (read-only, usually 30-90 seconds)...\n\n", Version)
	}
	raw, rawJSON, err := collect()
	if err != nil {
		fmt.Println("error:", err)
		exit(1)
	}
	findings := analyze(raw, time.Now())
	if *jsonOut {
		b, _ := json.MarshalIndent(map[string]any{"version": Version, "score": score(findings), "findings": findings, "collected": json.RawMessage(rawJSON)}, "", "  ")
		fmt.Println(string(b))
		return
	}

	host := "PC"
	if raw.System != nil {
		host = raw.System.Host
		fmt.Printf("%s - %s - %s %s\n\n", raw.System.Host, raw.System.Model, raw.System.OS, raw.System.Version)
	}
	for _, f := range findings {
		fmt.Printf("%s %s\n", marker(f.Sev), f.Title)
		if f.Detail != "" {
			fmt.Printf("      %s\n", f.Detail)
		}
	}
	fmt.Printf("\nScore: %d/100 (%s)\n", score(findings), verdict(score(findings)))

	outDir := *outFlag
	if outDir == "" {
		home, _ := os.UserHomeDir()
		outDir = filepath.Join(home, "Documents", "PW Tune-up", host+"-"+time.Now().Format("20060102-1504"))
	}

	// ---- fixes ------------------------------------------------------------------------------------
	var offer []Finding
	for _, f := range findings {
		if f.Fix != "" {
			offer = append(offer, f)
		}
	}
	if *deep {
		offer = append(offer, Finding{ID: "deep", Fix: "components", FixLabel: "DISM component cleanup (several minutes)", FixAdmin: true})
	}
	var results []FixResult
	if len(offer) > 0 && !*reportOnly {
		fmt.Printf("\n%d fix(es) available:\n", len(offer))
		for i, f := range offer {
			note := ""
			if f.FixAdmin && !admin {
				note = "  (needs administrator: will be skipped)"
			}
			fmt.Printf("  %d) %s%s\n", i+1, f.FixLabel, note)
		}
		in := bufio.NewReader(os.Stdin)
		mode := "a"
		if !*yes && !*dry {
			mode = strings.ToLower(ask(in, "\nApply them? [a]ll, [e]ach one, [n]one (default none): "))
		}
		var chosen []Finding
		for _, f := range offer {
			if f.FixAdmin && !admin {
				continue
			}
			take := false
			switch {
			case mode == "a" || mode == "all":
				take = true
			case mode == "e" || mode == "each":
				take = yesNo(in, "  "+f.FixLabel+"? [y/N] ")
			}
			if take && f.Confirm != "" && !*dry {
				take = yesNo(in, "  "+f.Confirm+" [y/N] ")
			}
			if take {
				chosen = append(chosen, f)
			}
		}
		if len(chosen) > 0 {
			os.MkdirAll(outDir, 0o755)
			rp := FixResult{ID: "restorepoint", Msg: "not attempted: making one needs administrator"}
			if admin {
				fmt.Println("\nCreating a System Restore point first...")
				rp = fix("restorepoint", nil, outDir, *dry)
			} else {
				fmt.Println()
			}
			rp.Label, rp.Dry = "Restore point", *dry
			results = append(results, rp)
			fmt.Printf("  %s %s\n", okMark(rp.OK), rp.Msg)
			// No restore point, no silent changes: ask, and refuse when nobody can be asked.
			if !rp.OK && !*dry {
				goOn := false
				switch {
				case *noRestore:
					fmt.Println("  --no-restore-point: applying the fixes without one.")
					goOn = true
				case interactive():
					goOn = yesNo(in, "  There is no restore point to go back to. Apply the fixes anyway? [y/N] ")
				default:
					fmt.Println("  Not applying any fix without a restore point (no one to ask; --no-restore-point overrides).")
				}
				if !goOn {
					results = append(results, FixResult{ID: "fixes", Label: "Fixes", Msg: "none applied: no restore point"})
					chosen = nil
				}
			}
			for _, f := range chosen {
				fmt.Printf("%s...\n", f.FixLabel)
				r := fix(f.Fix, f.FixArg, outDir, *dry)
				r.Label, r.Dry = f.FixLabel, *dry
				results = append(results, r)
				fmt.Printf("  %s %s\n", okMark(r.OK), r.Msg)
			}
		}
	}

	path, err := writeReport(outDir, raw, rawJSON, findings, results)
	if err != nil {
		fmt.Println("could not write the report:", err)
		exit(1)
	}
	fmt.Println("\nReport:", path)
	if !*noOpen {
		openFile(path)
	}
	exit(0)
}

func marker(sev string) string {
	switch sev {
	case SevBad:
		return "[!!]"
	case SevWarn:
		return "[! ]"
	case SevOK:
		return "[ok]"
	}
	return "[i ]"
}

func okMark(ok bool) string {
	if ok {
		return "done:"
	}
	return "FAILED:"
}

// interactive reports whether stdin is a console someone can answer at.
func interactive() bool {
	st, err := os.Stdin.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func ask(in *bufio.Reader, prompt string) string {
	fmt.Print(prompt)
	s, _ := in.ReadString('\n')
	return strings.TrimSpace(s)
}

func yesNo(in *bufio.Reader, prompt string) bool {
	s := strings.ToLower(ask(in, prompt))
	return s == "y" || s == "yes"
}

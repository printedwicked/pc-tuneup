//go:build windows

package main

import (
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

func isAdmin() bool { return windows.GetCurrentProcessToken().IsElevated() }

// relaunchElevated starts this exe again through the UAC prompt with the same arguments.
// It returns an error if the person declined the prompt.
func relaunchElevated(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	var q []string
	for _, a := range args {
		q = append(q, syscall.EscapeArg(a))
	}
	cwd, _ := os.Getwd()
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(strings.Join(q, " "))
	dir, _ := windows.UTF16PtrFromString(cwd)
	return windows.ShellExecute(0, verb, file, params, dir, windows.SW_NORMAL)
}

func openFile(path string) {
	_ = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", path).Start()
}

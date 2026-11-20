//go:build !windows

package main

import "errors"

// pw-tuneup only does real work on Windows; these stubs let the analysis and tests build anywhere.
func isAdmin() bool                        { return false }
func relaunchElevated(args []string) error { return errors.New("windows only") }
func openFile(path string)                 {}

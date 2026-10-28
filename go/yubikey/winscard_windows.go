//go:build windows

package yubikey

import "golang.org/x/sys/windows"

// winscard is the PC/SC library piv-go calls. piv-go loads it by bare name
// (syscall.NewLazyDLL("Winscard.dll")), which Windows looks up in the
// executable's directory before System32: for an app run from Downloads, a
// Winscard.dll downloaded beside it would be loaded and see every PIN.
// Loading it from System32 first makes piv-go's load find that module, which
// Windows reuses for any later load by the same name.
var winscard = windows.NewLazySystemDLL("winscard.dll")

func init() {
	// Every Windows install has it; should it ever fail, piv-go's own load
	// reports the missing PC/SC service as before.
	_ = winscard.Load()
}

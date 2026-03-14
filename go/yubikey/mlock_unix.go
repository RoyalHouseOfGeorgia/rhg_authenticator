//go:build !windows

package yubikey

import (
	"log"
	"syscall"
)

// mlockBuffer locks a byte slice into physical RAM to prevent swapping.
// If mlock fails (e.g., insufficient permissions), a warning is logged
// but execution continues — the PIN remains in-process memory.
func mlockBuffer(buf []byte) {
	if len(buf) == 0 {
		return
	}
	if err := syscall.Mlock(buf); err != nil {
		log.Printf("warning: failed to lock sensitive memory: %v", err)
	}
}

//go:build !windows

package yubikey

import "syscall"

// mlockBuffer locks a byte slice into physical RAM to prevent swapping.
func mlockBuffer(buf []byte) error {
	if len(buf) == 0 {
		return nil
	}
	return syscall.Mlock(buf)
}

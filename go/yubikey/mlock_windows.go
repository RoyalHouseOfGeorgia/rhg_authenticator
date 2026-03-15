//go:build windows

package yubikey

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

var (
	kernel32    = syscall.NewLazyDLL("kernel32.dll")
	virtualLock = kernel32.NewProc("VirtualLock")
)

// mlockBuffer locks a byte slice into physical RAM to prevent swapping.
func mlockBuffer(buf []byte) error {
	if len(buf) == 0 {
		return nil
	}
	ret, _, err := virtualLock.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	runtime.KeepAlive(buf)
	if ret == 0 {
		return fmt.Errorf("VirtualLock: %w", err)
	}
	return nil
}

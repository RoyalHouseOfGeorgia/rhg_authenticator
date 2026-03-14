//go:build windows

package yubikey

import (
	"log"
	"runtime"
	"syscall"
	"unsafe"
)

var (
	kernel32    = syscall.NewLazyDLL("kernel32.dll")
	virtualLock = kernel32.NewProc("VirtualLock")
)

// mlockBuffer locks a byte slice into physical RAM to prevent swapping.
// If VirtualLock fails, a warning is logged but execution continues.
func mlockBuffer(buf []byte) {
	if len(buf) == 0 {
		return
	}
	ret, _, err := virtualLock.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	runtime.KeepAlive(buf)
	if ret == 0 {
		log.Printf("warning: failed to lock sensitive memory: %v", err)
	}
}

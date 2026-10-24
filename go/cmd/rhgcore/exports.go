package main

/*
#include <stdlib.h>

// rhg_event_cb receives each event as UTF-8 JSON, {"event":name,"data":payload}.
// The string is valid only during the call and is never freed by the callee.
// The callback may run on any thread, synchronously on the goroutine that
// emits the event (possibly inside an RHGCall on another thread), and must
// not block: a UI copies the string and marshals it to its main thread.
typedef void (*rhg_event_cb)(const char*);

static inline void rhg_call_event(rhg_event_cb cb, const char* s) { cb(s); }
*/
import "C"

import (
	"os"
	"unsafe"

	"github.com/royalhouseofgeorgia/rhg-authenticator/service/rpc"
)

// invokeEventCallback passes event to fn as a NUL-terminated C string it
// frees after fn returns.
func invokeEventCallback(fn *[0]byte, event []byte) {
	s := C.CString(string(event))
	defer C.free(unsafe.Pointer(s))
	C.rhg_call_event(C.rhg_event_cb(fn), s)
}

// cChar is C.char under a name the tests can use (test files can't import
// "C").
type cChar = C.char

// goString returns the C string p, "" for NULL.
func goString(p *C.char) string {
	if p == nil {
		return ""
	}
	return C.GoString(p)
}

// RHGCall runs method with paramsJSON (a JSON object; NULL or "" for none)
// and returns the UTF-8 JSON response envelope, which the caller frees with
// RHGFree. It blocks for as long as the method runs, so it must not be
// called on a UI thread. It never returns NULL.
//
//export RHGCall
func RHGCall(method, paramsJSON *C.char) *C.char {
	return call(
		func() (string, []byte) { return goString(method), []byte(goString(paramsJSON)) },
		rpc.Dispatch,
		func(out []byte) *C.char { return C.CString(string(out)) },
	)
}

// RHGFree frees a string returned by RHGCall; NULL is ignored.
//
//export RHGFree
func RHGFree(p *C.char) {
	C.free(unsafe.Pointer(p))
}

// RHGSetEventCallback makes cb receive every later event; NULL detaches it.
// An event already being delivered when cb is replaced may still reach the
// previous callback, so a host keeps every callback it registers valid for
// the life of the process.
//
//export RHGSetEventCallback
func RHGSetEventCallback(cb C.rhg_event_cb) {
	if cb == nil {
		rpc.SetEventCallback(nil)
		return
	}
	fn := (*[0]byte)(cb)
	rpc.SetEventCallback(func(event []byte) { invokeEventCallback(fn, event) })
}

// RHGMainCLI handles the command-line invocations (--version,
// --verify-update-zip) before any UI starts. It returns -1 when argv is not
// one, and the UI should start; otherwise the process exit code.
//
//export RHGMainCLI
func RHGMainCLI(argc C.int, argv **C.char) C.int {
	if argc <= 0 || argv == nil {
		return -1
	}
	args := make([]string, 0, int(argc))
	for _, p := range unsafe.Slice(argv, int(argc)) {
		args = append(args, goString(p))
	}
	return C.int(mainCLI(args, os.Stdout, os.Stderr))
}

// Package safego launches goroutines with panic recovery.
//
// An unrecovered panic in any goroutine terminates the whole process, and in
// release builds nothing would be logged. Every production go statement must
// go through Go so a panic is recovered, logged, and surfaced to the user
// instead of killing the app. A guard test enforces that no other package
// uses a bare go statement.
package safego

import (
	"fmt"
	"log"
	"os"
	"runtime"
)

// stackBufSize is the maximum number of bytes of stack trace captured on panic.
const stackBufSize = 4096

// handler receives recovered panics. Nil means defaultHandler.
var handler func(r any, stack []byte)

// SetPanicHandler installs h as the handler for panics recovered by Go.
// A nil h restores the default handler (stderr + stdlib log).
//
// It is not safe to call concurrently with Go: set it once at startup,
// before any goroutine is launched.
func SetPanicHandler(h func(r any, stack []byte)) {
	handler = h
}

// Go runs fn in a new goroutine. A panic in fn is recovered, its stack is
// captured, and the panic handler is called. If the handler itself panics,
// the default handler is used instead.
func Go(fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				buf := make([]byte, stackBufSize)
				n := runtime.Stack(buf, false)
				dispatch(r, buf[:n])
			}
		}()
		fn()
	}()
}

// dispatch calls the installed handler (or the default) and falls back to the
// default handler if the installed one panics.
func dispatch(r any, stack []byte) {
	h := handler
	if h == nil {
		defaultHandler(r, stack)
		return
	}
	defer func() {
		if hr := recover(); hr != nil {
			// The default handler logs through the same stdlib logger the
			// installed handler may have just panicked in; never let that
			// second failure escape.
			defer func() { _ = recover() }()
			defaultHandler(fmt.Sprintf("%v (panic handler also panicked: %v)", r, hr), stack)
		}
	}()
	h(r, stack)
}

// defaultHandler writes the panic to stderr and to the stdlib logger, which
// the app redirects into its error log via debuglog.CaptureStdlib.
func defaultHandler(r any, stack []byte) {
	fmt.Fprintf(os.Stderr, "goroutine panic: %v\n%s\n", r, stack)
	log.Printf("PANIC (goroutine): %v %s", r, stack)
}

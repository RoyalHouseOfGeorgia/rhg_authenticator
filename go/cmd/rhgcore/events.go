package main

import "sync/atomic"

// eventCallback holds the host's C event callback and forwards rpc events to
// it. The function pointer lives in an atomic.Pointer because events are
// emitted from any goroutine while the host may replace or clear it.
type eventCallback struct {
	fn atomic.Pointer[[0]byte] // the C function pointer; nil = detached
	// invoke calls fn with event (the C trampoline in production).
	invoke func(fn *[0]byte, event []byte)
	// setSink is rpc.SetEventCallback in production.
	setSink func(func([]byte))
}

// set makes fn receive every later event; nil detaches the callback.
func (e *eventCallback) set(fn *[0]byte) {
	e.fn.Store(fn)
	if fn == nil {
		e.setSink(nil)
		return
	}
	e.setSink(e.emit)
}

// emit passes event to the current callback, if any.
func (e *eventCallback) emit(event []byte) {
	if fn := e.fn.Load(); fn != nil {
		e.invoke(fn, event)
	}
}

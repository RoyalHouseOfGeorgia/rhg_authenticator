package main

import "github.com/royalhouseofgeorgia/rhg-authenticator/service/rpc"

// call runs one RHGCall: in converts the C arguments, dispatch runs the
// method and out converts the envelope to the C result. A panic in any of the
// three returns out(rpc.InternalEnvelope()) instead, so no panic unwinds into
// the C caller. (rpc.Dispatch recovers and logs its own panics; this guard
// covers the conversions around it.)
func call[R any](in func() (string, []byte), dispatch func(method string, params []byte) []byte, out func([]byte) R) (res R) {
	defer func() {
		if recover() != nil {
			res = out(rpc.InternalEnvelope())
		}
	}()
	method, params := in()
	return out(dispatch(method, params))
}

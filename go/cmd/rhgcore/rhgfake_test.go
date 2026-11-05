//go:build rhgfake

package main

import (
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/service/rpc"
)

func TestRHGCall_FakeBuildPanicIsInternal(t *testing.T) {
	if got, want := rhgCall(t, "test.panic", `{}`, false, false), string(rpc.InternalEnvelope()); got != want {
		t.Fatalf("test.panic = %s, want %s", got, want)
	}
	if got := rhgCall(t, "app.canQuit", "", false, true); got != `{"ok":true,"result":{"dirty":false}}` {
		t.Fatalf("app.canQuit after a panic = %s", got)
	}
}

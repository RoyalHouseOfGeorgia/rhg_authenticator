package rpc

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
)

func TestEvents_Emit(t *testing.T) {
	e := newJSONEvents(nil)
	e.Emit("dropped", 1) // no sink: dropped, no panic

	rec := &sinkRecorder{}
	e.SetSink(rec.add)
	e.Emit(service.EventSignConnecting, nil)
	if n := len(rec.all()); n != 1 {
		t.Fatalf("delivered %d events, want 1", n)
	}

	e.SetSink(nil)
	e.Emit(service.EventHistoryChanged, nil)
	if len(rec.all()) != 1 {
		t.Error("event delivered after SetSink(nil)")
	}
}

func TestEvents_EncodeFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), debuglog.FileName)
	e := newJSONEvents(debuglog.New(path))
	rec := &sinkRecorder{}
	e.SetSink(rec.add)
	e.Emit("bad\nname", map[string]any{"secret-value": make(chan int)})
	if len(rec.all()) != 0 {
		t.Error("unencodable event delivered")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if log := string(data); !strings.Contains(log, "rpc: dropped event bad name: encoding failed") || strings.Contains(log, "secret-value") {
		t.Errorf("log = %q", log)
	}
}

func TestEvents_Concurrent(t *testing.T) {
	e := newJSONEvents(nil)
	var a, b sinkRecorder
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				if i%2 == 0 {
					e.Emit("x", i)
					continue
				}
				switch i % 3 {
				case 0:
					e.SetSink(a.add)
				case 1:
					e.SetSink(b.add)
				default:
					e.SetSink(nil)
				}
			}
		}()
	}
	wg.Wait()
	for _, ev := range append(a.all(), b.all()...) {
		if !strings.HasPrefix(ev, `{"event":"x","data":`) {
			t.Fatalf("event = %s", ev)
		}
	}
}

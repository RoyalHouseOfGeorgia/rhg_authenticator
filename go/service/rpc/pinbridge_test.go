package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
)

// pinMarker is a PIN that must never appear in an event, response or log.
const pinMarker = "73519468"

// pinHarness drives a ready server's PIN bridge directly as the service's
// Prompter, logging to its own diagnostic log.
type pinHarness struct {
	srv     *server
	sink    *eventSink
	logPath string
	resps   []string // every Dispatch response
}

func newPINHarness(t *testing.T) *pinHarness {
	t.Helper()
	path := filepath.Join(t.TempDir(), debuglog.FileName)
	logger := debuglog.New(path)
	h := &pinHarness{srv: readyServer(nil, logger), sink: newEventSink(), logPath: path}
	h.srv.events.logger.Store(logger)
	h.srv.events.SetSink(h.sink.add)
	return h
}

func (h *pinHarness) call(t testing.TB, method, params string) envelope {
	t.Helper()
	env := dispatch(t, h.srv, method, params)
	h.resps = append(h.resps, env.raw)
	return env
}

type pinOutcome struct {
	pin      string
	remember bool
	err      error
}

// request runs RequestPIN on its own goroutine, waits for its nth
// pin.request event and returns the request and the outcome channel.
func (h *pinHarness) request(t testing.TB, ctx context.Context, rememberDefault bool, n int) (pinRequestEvent, <-chan pinOutcome) {
	t.Helper()
	out := make(chan pinOutcome, 1)
	go func() {
		pin, remember, err := h.srv.pins.RequestPIN(ctx, rememberDefault)
		out <- pinOutcome{pin, remember, err}
	}()
	var req pinRequestEvent
	if err := json.Unmarshal(h.sink.wait(t, EventPINRequest, n), &req); err != nil {
		t.Fatal(err)
	}
	return req, out
}

func receive(t testing.TB, out <-chan pinOutcome) pinOutcome {
	t.Helper()
	select {
	case o := <-out:
		return o
	case <-time.After(waitTimeout):
		t.Fatal("RequestPIN did not return")
		return pinOutcome{}
	}
}

func idParams(id uint64, extra string) string {
	return `{"requestId":` + strconv.FormatUint(id, 10) + extra + `}`
}

// assertNoPIN fails if the PIN marker is in any event, response or the log.
func (h *pinHarness) assertNoPIN(t *testing.T) {
	t.Helper()
	for _, e := range h.sink.all() {
		if strings.Contains(e, pinMarker) {
			t.Errorf("event carries the PIN: %s", e)
		}
	}
	for _, r := range h.resps {
		if strings.Contains(r, pinMarker) {
			t.Errorf("response carries the PIN: %s", r)
		}
	}
	data, err := os.ReadFile(h.logPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if strings.Contains(string(data), pinMarker) {
		t.Errorf("log carries the PIN:\n%s", data)
	}
}

func TestPIN_SubmitAndCancel(t *testing.T) {
	h := newPINHarness(t)
	bg := context.Background()

	req, out := h.request(t, bg, true, 1)
	if req != (pinRequestEvent{RequestID: 1, RememberDefault: true, MaxBytes: service.PIVMaxPINBytes}) {
		t.Errorf("pin.request = %+v", req)
	}
	if env := h.call(t, "pin.submit", idParams(1, `,"pin":"`+pinMarker+`","remember":true`)); env.raw != `{"ok":true,"result":{}}` {
		t.Errorf("pin.submit = %s", env.raw)
	}
	if o := receive(t, out); o != (pinOutcome{pinMarker, true, nil}) {
		t.Errorf("outcome = %+v", o)
	}

	req, out = h.request(t, bg, false, 2)
	if req.RequestID != 2 || req.RememberDefault {
		t.Errorf("pin.request = %+v", req)
	}
	h.call(t, "pin.cancel", idParams(2, "")).ok(t, nil)
	if o := receive(t, out); o != (pinOutcome{}) {
		t.Errorf("cancel outcome = %+v", o)
	}
	if n := len(h.sink.named(t, EventPINDismiss)); n != 0 {
		t.Errorf("%d pin.dismiss for answered requests", n)
	}
	h.assertNoPIN(t)
}

func TestPIN_StaleAndUnknownRequests(t *testing.T) {
	h := newPINHarness(t)
	// Nothing pending.
	h.call(t, "pin.submit", idParams(1, `,"pin":"`+pinMarker+`"`)).fails(t, CodeInput, errNoPINRequest.msg)
	h.call(t, "pin.cancel", idParams(1, "")).fails(t, CodeInput, errNoPINRequest.msg)

	_, out := h.request(t, context.Background(), false, 1)
	h.call(t, "pin.submit", idParams(2, `,"pin":"`+pinMarker+`"`)).fails(t, CodeInput, errNoPINRequest.msg)
	h.call(t, "pin.cancel", idParams(0, "")).fails(t, CodeInput, errNoPINRequest.msg)

	// A second request while one is pending is refused at once.
	if pin, _, err := h.srv.pins.RequestPIN(context.Background(), false); pin != "" || !errors.Is(err, errPINPending) {
		t.Errorf("concurrent RequestPIN = %q, %v", pin, err)
	}

	h.call(t, "pin.submit", idParams(1, `,"pin":"`+pinMarker+`"`)).ok(t, nil)
	if o := receive(t, out); o.pin != pinMarker || o.err != nil {
		t.Errorf("outcome = %+v", o)
	}
	// Answered: a repeat is stale.
	h.call(t, "pin.submit", idParams(1, `,"pin":"`+pinMarker+`"`)).fails(t, CodeInput, errNoPINRequest.msg)
	h.assertNoPIN(t)
}

func TestPIN_ContextEndsDismisses(t *testing.T) {
	h := newPINHarness(t)

	ctx, cancel := context.WithCancel(context.Background())
	_, out := h.request(t, ctx, false, 1)
	cancel()
	if o := receive(t, out); o.pin != "" || !errors.Is(o.err, context.Canceled) {
		t.Errorf("outcome = %+v", o)
	}
	if got := h.sink.wait(t, EventPINDismiss, 1); string(got) != `{"requestId":1}` {
		t.Errorf("pin.dismiss = %s", got)
	}
	h.call(t, "pin.submit", idParams(1, `,"pin":"`+pinMarker+`"`)).fails(t, CodeInput, errNoPINRequest.msg)

	tctx, tcancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer tcancel()
	_, out = h.request(t, tctx, false, 2)
	if o := receive(t, out); !errors.Is(o.err, context.DeadlineExceeded) {
		t.Errorf("timeout outcome = %+v", o)
	}
	if got := h.sink.wait(t, EventPINDismiss, 2); string(got) != `{"requestId":2}` {
		t.Errorf("pin.dismiss = %s", got)
	}
	h.call(t, "pin.cancel", idParams(2, "")).fails(t, CodeInput, errNoPINRequest.msg)
	h.assertNoPIN(t)
}

// TestPIN_AnswerRacesContext answers each request from inside the pin.request
// emit with the ctx already done, so RequestPIN sees both at once (select
// picks either): the answer cleared the slot first, so it is always the
// outcome.
func TestPIN_AnswerRacesContext(t *testing.T) {
	events := newJSONEvents(nil)
	b := &pinBridge{events: events}
	var answerErr error
	events.SetSink(func(data []byte) {
		var ev struct {
			Event string
			Data  pinRequestEvent
		}
		if err := json.Unmarshal(data, &ev); err == nil && ev.Event == EventPINRequest {
			answerErr = b.answer(ev.Data.RequestID, pinAnswer{pin: pinMarker})
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for range 200 {
		pin, _, err := b.RequestPIN(ctx, false)
		if answerErr != nil || err != nil || pin != pinMarker {
			t.Fatalf("outcome %q, %v (answer: %v)", pin, err, answerErr)
		}
	}
}

func TestPIN_Shutdown(t *testing.T) {
	h := newPINHarness(t)
	_, out := h.request(t, context.Background(), false, 1)
	h.srv.pins.shutdown()
	if o := receive(t, out); o != (pinOutcome{}) {
		t.Errorf("outcome = %+v", o)
	}
	if got := h.sink.wait(t, EventPINDismiss, 1); string(got) != `{"requestId":1}` {
		t.Errorf("pin.dismiss = %s", got)
	}
	// Later requests are cancelled without a prompt.
	if pin, _, err := h.srv.pins.RequestPIN(context.Background(), false); pin != "" || err != nil {
		t.Errorf("RequestPIN after shutdown = %q, %v", pin, err)
	}
	if n := len(h.sink.named(t, EventPINRequest)); n != 1 {
		t.Errorf("%d pin.request events", n)
	}
	h.srv.pins.shutdown() // nothing pending: no-op
	if n := len(h.sink.named(t, EventPINDismiss)); n != 1 {
		t.Errorf("%d pin.dismiss events", n)
	}
}

func TestPIN_NeverLeaks(t *testing.T) {
	h := newPINHarness(t)
	_, out := h.request(t, context.Background(), false, 1)
	for _, params := range []string{
		`{"requestId":1,"pin":"` + pinMarker + `","x":1}`,
		`{"requestId":1,"pin":"` + pinMarker + `"`,
		`{"requestId":"` + pinMarker + `"}`,
		`{"requestId":1,"pin":"` + pinMarker + `"} "` + pinMarker + `"`,
		`["` + pinMarker + `"]`,
	} {
		h.call(t, "pin.submit", params).fails(t, CodeInput, msgBadParams)
	}

	// A panic carrying the PIN is logged by type only.
	submit := h.srv.methods["pin.submit"]
	h.srv.methods["pin.submit"] = func(s *server, params []byte) (any, error) {
		var p pinSubmitParams
		_ = json.Unmarshal(params, &p)
		panic(errors.New("bad PIN " + p.PIN))
	}
	h.call(t, "pin.submit", idParams(1, `,"pin":"`+pinMarker+`"`)).fails(t, CodeInternal, msgInternal)
	h.srv.methods["pin.submit"] = submit

	h.call(t, "pin.submit", idParams(1, `,"pin":"`+pinMarker+`"`)).ok(t, nil)
	if o := receive(t, out); o.pin != pinMarker {
		t.Errorf("outcome = %+v", o)
	}
	data, err := os.ReadFile(h.logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "rpc: panic in pin.submit: *errors.errorString") {
		t.Errorf("panic not logged:\n%s", data)
	}
	h.assertNoPIN(t)
}

func TestPIN_CallbackPanicFreesSlot(t *testing.T) {
	h := newPINHarness(t)
	h.srv.events.SetSink(func(b []byte) {
		if strings.Contains(string(b), EventPINRequest) {
			panic("host callback failed")
		}
	})
	func() {
		defer func() { _ = recover() }()
		_, _, _ = h.srv.pins.RequestPIN(context.Background(), false)
	}()

	h.srv.events.SetSink(h.sink.add)
	ctx, cancel := context.WithCancel(context.Background())
	_, out := h.request(t, ctx, false, 1)
	cancel()
	if o := receive(t, out); !errors.Is(o.err, context.Canceled) {
		t.Errorf("next request err = %v, want context.Canceled (the slot was freed)", o.err)
	}
}

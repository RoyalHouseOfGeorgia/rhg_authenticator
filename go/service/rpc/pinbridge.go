package rpc

import (
	"context"
	"errors"
	"sync"

	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
)

// errPINPending is RequestPIN's error when a request is already waiting.
var errPINPending = errors.New("rpc: a PIN request is already pending")

// errNoPINRequest is pin.submit's or pin.cancel's error when requestId is not
// the pending request (none pending, already answered or dismissed).
var errNoPINRequest = &inputError{"This PIN request is no longer active."}

// pinBridge implements service.Prompter over events: RequestPIN emits
// pin.request and waits for pin.submit or pin.cancel. It holds one request at
// a time. Whoever clears the pending slot (an answer, the request's ctx, or
// shutdown) owns the outcome and sends it, so each request resolves exactly
// once. The PIN is passed through only; it is never logged or emitted.
type pinBridge struct {
	events *jsonEvents

	mu      sync.Mutex // guards the fields below
	seq     uint64     // the last requestId issued
	pending *pinRequest
	closed  bool // shut down: every request is cancelled
}

var _ service.Prompter = (*pinBridge)(nil)

type pinRequest struct {
	id     uint64
	answer chan pinAnswer // buffered: the slot's clearer sends exactly once
}

type pinAnswer struct {
	pin      string
	remember bool
}

type pinRequestEvent struct {
	RequestID       uint64 `json:"requestId"`
	RememberDefault bool   `json:"rememberDefault"`
	MaxBytes        int    `json:"maxBytes"`
}

type pinDismissEvent struct {
	RequestID uint64 `json:"requestId"`
}

// RequestPIN emits pin.request and waits for its answer. A cancel or a
// shutdown returns an empty pin; when ctx ends first the request is dismissed
// and ctx.Err() returned.
func (b *pinBridge) RequestPIN(ctx context.Context, rememberDefault bool) (string, bool, error) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return "", false, nil
	}
	if b.pending != nil {
		b.mu.Unlock()
		return "", false, errPINPending
	}
	b.seq++
	req := &pinRequest{id: b.seq, answer: make(chan pinAnswer, 1)}
	b.pending = req
	b.mu.Unlock()
	// Frees the slot on every exit, including a panic in the host's event
	// callback; a no-op once an answer, the timeout or shutdown took it.
	defer b.take(req.id)

	b.events.Emit(EventPINRequest, pinRequestEvent{
		RequestID:       req.id,
		RememberDefault: rememberDefault,
		MaxBytes:        service.PIVMaxPINBytes,
	})
	select {
	case a := <-req.answer:
		return a.pin, a.remember, nil
	case <-ctx.Done():
		if _, ok := b.take(req.id); !ok {
			// An answer cleared the slot first and is being sent.
			a := <-req.answer
			return a.pin, a.remember, nil
		}
		b.events.Emit(EventPINDismiss, pinDismissEvent{RequestID: req.id})
		return "", false, ctx.Err()
	}
}

// take clears and returns the pending request if its id is id.
func (b *pinBridge) take(id uint64) (*pinRequest, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	req := b.pending
	if req == nil || req.id != id {
		return nil, false
	}
	b.pending = nil
	return req, true
}

// answer delivers a to request id (an empty pin is a cancel).
func (b *pinBridge) answer(id uint64, a pinAnswer) error {
	req, ok := b.take(id)
	if !ok {
		return errNoPINRequest
	}
	req.answer <- a
	return nil
}

// shutdown cancels the pending request, emitting pin.dismiss for it, and
// makes every later RequestPIN return a cancel at once.
func (b *pinBridge) shutdown() {
	b.mu.Lock()
	b.closed = true
	req := b.pending
	b.pending = nil
	b.mu.Unlock()
	if req == nil {
		return
	}
	req.answer <- pinAnswer{}
	b.events.Emit(EventPINDismiss, pinDismissEvent{RequestID: req.id})
}

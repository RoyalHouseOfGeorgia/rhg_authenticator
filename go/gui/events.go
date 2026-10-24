package gui

import (
	"sync"

	"fyne.io/fyne/v2"
)

// Events delivers service events to UI handlers on the Fyne thread.
type Events struct {
	mu       sync.Mutex
	handlers map[string]func(any)
}

// NewEvents returns an Events with no handlers.
func NewEvents() *Events {
	return &Events{handlers: map[string]func(any){}}
}

// On sets the handler for name, replacing any previous one.
func (e *Events) On(name string, h func(any)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.handlers[name] = h
}

// Emit runs the handler for name, if any, inside fyne.Do.
func (e *Events) Emit(name string, payload any) {
	e.mu.Lock()
	h := e.handlers[name]
	e.mu.Unlock()
	if h != nil {
		fyne.Do(func() { h(payload) })
	}
}

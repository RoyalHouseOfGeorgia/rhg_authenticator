package rpc

import (
	"encoding/json"
	"sync/atomic"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
)

// Event names emitted by the rpc layer itself, besides the service.Event*
// names.
const (
	// EventPINRequest asks the host to prompt for the YubiKey PIN. Payload:
	// {requestId, rememberDefault, maxBytes}. Answer with pin.submit or
	// pin.cancel.
	EventPINRequest = "pin.request"
	// EventPINDismiss withdraws a pin.request (timed out, operation cancelled
	// or shutdown). Payload: {requestId}.
	EventPINDismiss = "pin.dismiss"
	// EventUpdateStatus fires when the update offer changes. Payload: the
	// update.current status object.
	EventUpdateStatus = "update.status"
	// EventUpdateUpdated fires at most once, when the app was just updated
	// and the notice was not already pulled through update.current. Payload:
	// {version, releaseUrl}.
	EventUpdateUpdated = "update.updated"
	// EventInternalError fires after a background goroutine panicked (it is
	// logged); the host tells the user to restart. Payload: null.
	EventInternalError = "app.internalError"
)

// jsonEvents implements service.Events by encoding each event as JSON,
// {"event":name,"data":payload}, and passing it to the sink. It is created
// before the App (it goes into service.Config.Events); events emitted while no
// sink is set are dropped.
type jsonEvents struct {
	logger atomic.Pointer[debuglog.Logger]
	sink   atomic.Pointer[func([]byte)]
}

var _ service.Events = (*jsonEvents)(nil)

// newJSONEvents returns a jsonEvents with no sink that logs encoding failures to
// logger (which may be nil).
func newJSONEvents(logger *debuglog.Logger) *jsonEvents {
	e := &jsonEvents{}
	e.logger.Store(logger)
	return e
}

// SetSink makes sink receive every later event; nil detaches the current one.
// An Emit already in progress may still deliver to the previous sink.
func (e *jsonEvents) SetSink(sink func([]byte)) {
	if sink == nil {
		e.sink.Store(nil)
		return
	}
	e.sink.Store(&sink)
}

// attached reports whether a sink is set.
func (e *jsonEvents) attached() bool { return e.sink.Load() != nil }

// event is the JSON form of an emitted event.
type event struct {
	Event string `json:"event"`
	Data  any    `json:"data"`
}

// Emit encodes the event and calls the sink synchronously; the sink must not
// block (the host queues). A payload that fails to encode is logged by event
// name only and dropped.
func (e *jsonEvents) Emit(name string, payload any) {
	sink := e.sink.Load()
	if sink == nil {
		return
	}
	data, err := json.Marshal(event{Event: name, Data: payload})
	if err != nil {
		e.logger.Load().Log("rpc: dropped event " + logName(name) + ": encoding failed")
		return
	}
	(*sink)(data)
}

// maxLogNameRunes caps a method or event name in the diagnostic log.
const maxLogNameRunes = 64

// logName returns name sanitized and shortened for the diagnostic log.
func logName(name string) string {
	r := []rune(core.SanitizeForLog(name))
	if len(r) > maxLogNameRunes {
		r = r[:maxLogNameRunes]
	}
	return string(r)
}

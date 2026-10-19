// Package rpc exposes service.App as a JSON method surface for native front
// ends: Dispatch takes a method name and a JSON params object and returns a
// JSON envelope, and events go as JSON to the callback set with
// SetEventCallback. It holds no UI or security logic of its own and opens no
// network listener.
//
// The host sets the event callback, calls app.init (which opens the
// diagnostic log and creates the App) and then app.start once its UI listens.
// Every method except app.init, app.canQuit and app.shutdown needs a
// successful app.init; after app.shutdown only app.canQuit and app.shutdown
// are accepted. Rejected calls fail with CodeInput.
//
// Every response is an envelope:
//
//	{"ok":true,"result":<result>}
//	{"ok":false,"error":{"code":"…","message":"…","offerReport":false}}
//
// A void method's result is {}. offerReport is always present; reportId is
// added only when offerReport is true. message is user-facing. code is one of
// the Code constants: a host branches on the code and shows the message, and
// CodeFailed means "show the message" with nothing more specific to do.
// CodeInput always means a host programming error. Slices in results are []
// when empty, never null.
//
// Display strings: message, statusText, summary, summaryLine, countsLine,
// stopMessage, title, the KeyCheck status and details, the registry rows and
// columns, recordText's detail and revokeConfirm, and every *Filename are
// render-only text that may change in any release. Hosts show them as given
// and never compare or parse them; they branch only on ok, code, offerReport,
// and the typed fields (booleans, enums such as state, stopped, result and
// status, numbers and ids).
package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"runtime/debug"
	"sync"
	"sync/atomic"

	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
	"github.com/royalhouseofgeorgia/rhg-authenticator/host"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
	"github.com/royalhouseofgeorgia/rhg-authenticator/update"
)

// Error codes in an error envelope.
const (
	// CodeCancelled: the operation was cancelled (auth.cancelLogin, or the
	// PIN prompt in sign.sign). A cancelled bulk.run succeeds with stopped
	// "cancelled".
	CodeCancelled = "cancelled"
	// CodeBusy: a conflicting operation is running (service.ErrBusy).
	CodeBusy = "busy"
	// CodeNotLoggedIn: no usable GitHub session (service.ErrNotLoggedIn). A
	// session GitHub rejected is CodeSessionExpired.
	CodeNotLoggedIn = "notLoggedIn"
	// CodeSessionExpired: GitHub rejected the session, which is now logged out
	// (service.ErrSessionExpired).
	CodeSessionExpired = "sessionExpired"
	// CodeRegistryChanged: the registry changed upstream since it was fetched
	// (service.ErrRegistryChanged).
	CodeRegistryChanged = "registryChanged"
	// CodeNotFound: the requested item is unknown (service.ErrNotFound).
	CodeNotFound = "notFound"
	// CodeNothingToExport: there is nothing to export yet
	// (service.ErrNothingToExport); an information notice, not an error.
	CodeNothingToExport = "nothingToExport"
	// CodeLoginUnavailable: GitHub login can't work on this computer
	// (service.ErrLoginUnavailable); the host stops offering it.
	CodeLoginUnavailable = "loginUnavailable"
	// CodeFailed: any other service error.
	CodeFailed = "failed"
	// CodeInput: the request itself is malformed (unknown method, bad params).
	CodeInput = "input"
	// CodeInternal: the call panicked.
	CodeInternal = "internal"
)

// defaultServer is the process's server, behind Dispatch and
// SetEventCallback.
var defaultServer = newServer()

// Dispatch runs method on the process's server and returns the JSON envelope
// (see server.Dispatch). It is safe for concurrent use. It blocks for as long
// as the method runs — card, network, the PIN prompt (until pin.submit or
// pin.cancel from another call), or an update install in app.shutdown — so it
// must not be called on a UI thread.
func Dispatch(method string, params []byte) []byte {
	return defaultServer.Dispatch(method, params)
}

// SetEventCallback makes cb receive every later event as JSON,
// {"event":name,"data":payload}; nil detaches it. cb is called synchronously
// on the emitting goroutine (any goroutine, possibly inside a Dispatch call)
// and must not block. app.init requires a callback; app.shutdown detaches it.
func SetEventCallback(cb func([]byte)) {
	defaultServer.events.SetSink(cb)
}

// maxParamsBytes is the largest params object Dispatch decodes.
const maxParamsBytes = 1 << 20

// Fixed messages for requests rejected before reaching the service.
const (
	msgUnknownMethod = "Unknown method."
	msgBadParams     = "Invalid request parameters."
	msgInternal      = "An internal error occurred — please restart"
)

// inputError is a malformed request; its message is fixed and never echoes
// the request.
type inputError struct{ msg string }

func (e *inputError) Error() string { return e.msg }

var (
	errUnknownMethod = &inputError{msgUnknownMethod}
	errBadParams     = &inputError{msgBadParams}
)

// handler runs one method with its raw params.
type handler func(s *server, params []byte) (any, error)

// lifecycle is a server's state; it only moves forward, except that a failed
// app.init returns to stateNew.
type lifecycle int

const (
	stateNew lifecycle = iota
	stateInitializing
	stateReady
	stateShutDown
)

// anyStateMethods may be called in every state; the rest need stateReady.
var anyStateMethods = map[string]bool{"app.init": true, "app.canQuit": true, "app.shutdown": true}

// updateManager is the part of *update.Manager the server uses.
type updateManager interface {
	Run(ctx context.Context)
	ApplyIfReady(relaunch bool)
}

// server dispatches JSON method calls to the service.App it creates in
// app.init and owns until app.shutdown.
type server struct {
	methods map[string]handler
	events  *jsonEvents
	pins    *pinBridge
	logger  atomic.Pointer[debuglog.Logger] // the open diagnostic log; nil before app.init

	// Start-up dependencies, replaceable in tests.
	newKeyring func() ghapi.Keyring
	newService func(service.Config) (*service.App, error)
	newManager func(update.Config) updateManager

	mu      sync.Mutex // guards the fields below; never held across I/O or Emit
	state   lifecycle
	app     *service.App // set on entering stateReady, never cleared
	logs    *host.Logs
	dataDir string
	started bool
	manager updateManager
	cancel  context.CancelFunc // stops manager.Run
	update  updateState
}

// newServer returns a server in stateNew with the production dependencies.
func newServer() *server {
	events := newJSONEvents(nil)
	s := &server{
		methods:    methodTable(),
		events:     events,
		pins:       &pinBridge{events: events},
		newKeyring: ghapi.NewOSKeyring,
		newService: host.NewService,
		newManager: func(cfg update.Config) updateManager { return update.NewManager(cfg) },
	}
	addTestMethods(s)
	return s
}

// Dispatch runs method with params, a JSON object (empty for none), and
// returns the JSON envelope. It never panics: a panic on the call path is
// logged (method name, panic type and stack, never the value or params) and
// returned as CodeInternal. Methods that block (card, network, PIN prompt) do
// so on the calling goroutine.
func (s *server) Dispatch(method string, params []byte) (out []byte) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Load().Logf("rpc: panic in %s: %T\n%s", logName(method), r, debug.Stack())
			out = internalEnvelope
		}
	}()
	h, ok := s.methods[method]
	if !ok {
		return errorEnvelope(errUnknownMethod)
	}
	if !anyStateMethods[method] {
		if err := s.requireReady(); err != nil {
			return errorEnvelope(err)
		}
	}
	res, err := h(s, params)
	if err != nil {
		return errorEnvelope(err)
	}
	return mustMarshal(successBody{OK: true, Result: res})
}

type successBody struct {
	OK     bool `json:"ok"`
	Result any  `json:"result"`
}

type errorBody struct {
	OK    bool      `json:"ok"`
	Error errorInfo `json:"error"`
}

type errorInfo struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	OfferReport bool   `json:"offerReport"`
	ReportID    string `json:"reportId,omitempty"`
}

var internalEnvelope = mustMarshal(errorBody{Error: errorInfo{Code: CodeInternal, Message: msgInternal}})

// InternalEnvelope returns the CodeInternal envelope Dispatch returns for a
// panic, for a host's own panic guard around Dispatch.
func InternalEnvelope() []byte { return bytes.Clone(internalEnvelope) }

// mustMarshal encodes v, panicking on failure: every result type encodes, so
// a failure is a bug, reported through Dispatch's recover.
func mustMarshal(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}

func errorEnvelope(err error) []byte {
	return mustMarshal(errorBody{Error: classify(err)})
}

// classify maps err to its envelope error. Service error texts are
// user-facing by contract, so they are the message.
func classify(err error) errorInfo {
	var ie *inputError
	if errors.As(err, &ie) {
		return errorInfo{Code: CodeInput, Message: ie.msg}
	}
	if errors.Is(err, context.Canceled) {
		return errorInfo{Code: CodeCancelled, Message: err.Error()}
	}
	for _, m := range []struct {
		sentinel error
		code     string
	}{
		{service.ErrBusy, CodeBusy},
		{service.ErrNotLoggedIn, CodeNotLoggedIn},
		{service.ErrSessionExpired, CodeSessionExpired},
		{service.ErrRegistryChanged, CodeRegistryChanged},
		{service.ErrNotFound, CodeNotFound},
		{service.ErrNothingToExport, CodeNothingToExport},
		{service.ErrLoginUnavailable, CodeLoginUnavailable},
	} {
		if errors.Is(err, m.sentinel) {
			return errorInfo{Code: m.code, Message: err.Error()}
		}
	}
	info := errorInfo{Code: CodeFailed, Message: err.Error()}
	var se *service.SignError
	if errors.As(err, &se) && se.OfferReport {
		info.OfferReport, info.ReportID = true, se.ReportID
	}
	return info
}

// decodeParams decodes params, a single JSON object of at most
// maxParamsBytes, into v, rejecting unknown fields and trailing data. Empty
// params decode as {}. Any failure is errBadParams.
func decodeParams(params []byte, v any) error {
	if len(params) > maxParamsBytes {
		return errBadParams
	}
	trimmed := bytes.TrimSpace(params)
	if len(trimmed) == 0 {
		return nil
	}
	if trimmed[0] != '{' {
		return errBadParams
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errBadParams
	}
	if _, err := dec.Token(); err != io.EOF {
		return errBadParams
	}
	return nil
}

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"unsafe"

	"github.com/royalhouseofgeorgia/rhg-authenticator/buildinfo"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service/rpc"
)

// Test files can't import "C", so these helpers build and read C strings
// through the types the exported functions use, inferred from a zero value.

// cstr returns s as a NUL-terminated string of pointer type P (*C.char).
func cstr[P ~*E, E any](s string) P {
	b := append([]byte(s), 0)
	return P(unsafe.Pointer(&b[0]))
}

// cargv returns args as C strings of like's type.
func cargv[P ~*E, E any](like P, args ...string) []P {
	ptrs := make([]P, len(args))
	for i, a := range args {
		ptrs[i] = cstrLike(like, a)
	}
	return ptrs
}

// readC returns the NUL-terminated string at p.
func readC[P ~*E, E any](p P) string {
	base := unsafe.Pointer(p)
	n := 0
	for *(*byte)(unsafe.Add(base, n)) != 0 {
		n++
	}
	return string(unsafe.Slice((*byte)(base), n))
}

// rhgCall runs RHGCall through the C ABI types and frees the result.
func rhgCall(t *testing.T, method, params string, nilMethod, nilParams bool) string {
	t.Helper()
	var m, p = nilOf(RHGCall), nilOf(RHGCall)
	if !nilMethod {
		m = cstrLike(m, method)
	}
	if !nilParams {
		p = cstrLike(p, params)
	}
	res := RHGCall(m, p)
	if res == nil {
		t.Fatal("RHGCall returned NULL")
	}
	defer RHGFree(res)
	return readC(res)
}

// cstrLike is cstr with P inferred from like.
func cstrLike[P ~*E, E any](_ P, s string) P { return cstr[P](s) }

// nilOf returns a nil P, inferred from f's signature.
func nilOf[P any](func(P, P) P) (p P) { return p }

// unknownMethod is Dispatch's response to an unknown method.
const unknownMethod = `{"ok":false,"error":{"code":"input","message":"Unknown method.","offerReport":false}}`

func TestRHGCall(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		method, params       string
		nilMethod, nilParams bool
		want                 string
	}{
		{name: "both NULL", nilMethod: true, nilParams: true, want: unknownMethod},
		{name: "NULL method", nilMethod: true, params: `{}`, want: unknownMethod},
		{name: "unknown method", method: "no.such", params: `{}`, want: unknownMethod},
		{name: "NULL params", method: "app.canQuit", nilParams: true, want: `{"ok":true,"result":{"dirty":false}}`},
		{name: "empty params", method: "app.canQuit", params: "", want: `{"ok":true,"result":{"dirty":false}}`},
		{name: "bad params", method: "app.canQuit", params: `{"x":1}`,
			want: `{"ok":false,"error":{"code":"input","message":"Invalid request parameters.","offerReport":false}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := rhgCall(t, tc.method, tc.params, tc.nilMethod, tc.nilParams); got != tc.want {
				t.Errorf("RHGCall = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestRHGFree_NULL(t *testing.T) {
	RHGFree(nil)
}

func TestCall_PassesThrough(t *testing.T) {
	var gotMethod string
	var gotParams []byte
	out := call(
		func() (string, []byte) { return "m.x", []byte(`{"a":1}`) },
		func(m string, p []byte) []byte { gotMethod, gotParams = m, p; return []byte("env") },
		func(b []byte) string { return "out:" + string(b) },
	)
	if out != "out:env" || gotMethod != "m.x" || string(gotParams) != `{"a":1}` {
		t.Fatalf("call = %q (dispatched %q %q)", out, gotMethod, gotParams)
	}
}

func TestCall_RecoversPanics(t *testing.T) {
	internal := string(rpc.InternalEnvelope())
	in := func() (string, []byte) { return "m", nil }
	dispatch := func(string, []byte) []byte { return []byte("env") }
	conv := func(b []byte) string { return string(b) }
	outPanicsOnce := func() func([]byte) string {
		first := true
		return func(b []byte) string {
			if first {
				first = false
				panic("convert")
			}
			return string(b)
		}
	}
	for _, tc := range []struct {
		name     string
		in       func() (string, []byte)
		dispatch func(string, []byte) []byte
		out      func([]byte) string
	}{
		{"input conversion", func() (string, []byte) { panic("in") }, dispatch, conv},
		{"dispatch", in, func(string, []byte) []byte { panic("dispatch") }, conv},
		{"result conversion", in, dispatch, outPanicsOnce()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := call(tc.in, tc.dispatch, tc.out); got != internal {
				t.Fatalf("call = %s, want %s", got, internal)
			}
		})
	}
}

// fakeTrampoline records the events an eventCallback invokes, by function.
type fakeTrampoline struct {
	mu    sync.Mutex
	calls map[*[0]byte][]string
}

func (f *fakeTrampoline) invoke(fn *[0]byte, event []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[fn] = append(f.calls[fn], string(event))
}

// fnPtr returns a distinct non-nil stand-in for a C function pointer
// (new([0]byte) would not be distinct: zero-size values share an address).
func fnPtr() *[0]byte { return (*[0]byte)(unsafe.Pointer(new(int64))) }

func TestEventCallback(t *testing.T) {
	tr := &fakeTrampoline{calls: map[*[0]byte][]string{}}
	var sink func([]byte)
	sinkSet := 0
	e := &eventCallback{invoke: tr.invoke, setSink: func(f func([]byte)) { sink = f; sinkSet++ }}
	a, b := fnPtr(), fnPtr()

	e.emit([]byte("dropped")) // nothing attached
	e.set(a)
	if sink == nil {
		t.Fatal("set did not attach a sink")
	}
	sink([]byte("one"))
	e.set(b)
	sink([]byte("two"))
	e.set(nil)
	if sink != nil || sinkSet != 3 {
		t.Fatalf("set(nil) left the sink attached (set %d times)", sinkSet)
	}
	e.emit([]byte("late")) // an Emit racing the detach is dropped

	if got := tr.calls[a]; len(got) != 1 || got[0] != "one" {
		t.Errorf("first callback got %q", got)
	}
	if got := tr.calls[b]; len(got) != 1 || got[0] != "two" {
		t.Errorf("second callback got %q", got)
	}
	if len(tr.calls) != 2 {
		t.Errorf("calls = %v", tr.calls)
	}
}

func TestEventCallback_Concurrent(t *testing.T) {
	tr := &fakeTrampoline{calls: map[*[0]byte][]string{}}
	e := &eventCallback{invoke: tr.invoke, setSink: func(func([]byte)) {}}
	fn := fnPtr()
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 100 {
				e.set(fn)
				e.emit([]byte("x"))
				e.set(nil)
			}
		})
	}
	wg.Wait()
}

func TestRHGSetEventCallback_NULLDetaches(t *testing.T) {
	events.fn.Store(fnPtr())
	RHGSetEventCallback(nil)
	if events.fn.Load() != nil {
		t.Fatal("RHGSetEventCallback(NULL) left the callback attached")
	}
	// With no callback, app.init is refused.
	params, _ := json.Marshal(map[string]string{"dataDir": filepath.Join(t.TempDir(), "d")})
	got := rhgCall(t, "app.init", string(params), false, false)
	want := `{"ok":false,"error":{"code":"input","message":"Set the event callback before initializing the app.","offerReport":false}}`
	if got != want {
		t.Fatalf("app.init without a callback = %s", got)
	}
}

func TestMainCLI(t *testing.T) {
	for _, tc := range []struct {
		name   string
		argv   []string
		code   int
		stdout string
	}{
		{"empty argv", nil, -1, ""},
		{"program name only", []string{"rhgcore"}, -1, ""},
		{"ui args", []string{"rhgcore", "-psn_0_1"}, -1, ""},
		{"version", []string{"rhgcore", "--version"}, 0, version() + "\n"},
		{"version is not argv[0]", []string{"--version"}, -1, ""},
		{"verify usage", []string{"rhgcore", "--verify-update-zip"}, 2, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := mainCLI(tc.argv, &stdout, &stderr); code != tc.code || stdout.String() != tc.stdout {
				t.Fatalf("mainCLI = %d, stdout %q; want %d, %q", code, stdout.String(), tc.code, tc.stdout)
			}
		})
	}
}

func TestVersion(t *testing.T) {
	if got, want := version(), buildinfo.Version+wantVersionSuffix; got != want {
		t.Fatalf("version() = %q, want %q", got, want)
	}
}

// captureStdout runs f with os.Stdout redirected and returns what it wrote.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stdout")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	prev := os.Stdout
	os.Stdout = file
	defer func() { os.Stdout = prev }()
	f()
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestRHGMainCLI(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int32
	}{
		{"argc 0, NULL argv", int32(RHGMainCLI(0, nil))},
		{"argc -1, NULL argv", int32(RHGMainCLI(-1, nil))},
		{"argc 2, NULL argv", int32(RHGMainCLI(2, nil))},
	} {
		if tc.code != -1 {
			t.Errorf("%s: RHGMainCLI = %d, want -1", tc.name, tc.code)
		}
	}

	argv := cargv(nilOf(RHGCall), "rhgcore", "--version")
	var code int32
	out := captureStdout(t, func() { code = int32(RHGMainCLI(2, &argv[0])) })
	if code != 0 || out != version()+"\n" {
		t.Fatalf("RHGMainCLI --version = %d, %q", code, out)
	}
	if code := RHGMainCLI(1, &argv[0]); code != -1 {
		t.Fatalf("RHGMainCLI with argc 1 = %d, want -1", code)
	}
	other := cargv(nilOf(RHGCall), "rhgcore", "--other")
	if code := RHGMainCLI(2, &other[0]); code != -1 {
		t.Fatalf("RHGMainCLI --other = %d, want -1", code)
	}
	// A NULL entry reads as "".
	withNULL := append(argv[:1:1], nilOf(RHGCall))
	if code := RHGMainCLI(2, &withNULL[0]); code != -1 {
		t.Fatalf("RHGMainCLI with a NULL argument = %d, want -1", code)
	}
}

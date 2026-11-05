package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/royalhouseofgeorgia/rhg-authenticator/buildinfo"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service/rpc"
)

// cstr returns s as a NUL-terminated C string (Go memory, valid for the
// call it is passed to).
func cstr(s string) *cChar {
	b := append([]byte(s), 0)
	return (*cChar)(unsafe.Pointer(&b[0]))
}

// cargv returns args as C strings.
func cargv(args ...string) []*cChar {
	ptrs := make([]*cChar, len(args))
	for i, a := range args {
		ptrs[i] = cstr(a)
	}
	return ptrs
}

// readC returns the NUL-terminated string at p.
func readC(p *cChar) string {
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
	var m, p *cChar
	if !nilMethod {
		m = cstr(method)
	}
	if !nilParams {
		p = cstr(params)
	}
	res := RHGCall(m, p)
	if res == nil {
		t.Fatal("RHGCall returned NULL")
	}
	defer RHGFree(res)
	return readC(res)
}

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

// TestRHGSetEventCallback_NULLDetaches: with the callback detached, app.init
// is refused. (Attaching needs a real C function; the C smoke test covers it.)
func TestRHGSetEventCallback_NULLDetaches(t *testing.T) {
	rpc.SetEventCallback(func([]byte) {})
	RHGSetEventCallback(nil)
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
		{"version", []string{"rhgcore", "--version"}, 0, buildinfo.Display() + "\n"},
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

	argv := cargv("rhgcore", "--version")
	var code int32
	out := captureStdout(t, func() { code = int32(RHGMainCLI(2, &argv[0])) })
	if code != 0 || out != buildinfo.Display()+"\n" {
		t.Fatalf("RHGMainCLI --version = %d, %q", code, out)
	}
	if code := RHGMainCLI(1, &argv[0]); code != -1 {
		t.Fatalf("RHGMainCLI with argc 1 = %d, want -1", code)
	}
	other := cargv("rhgcore", "--other")
	if code := RHGMainCLI(2, &other[0]); code != -1 {
		t.Fatalf("RHGMainCLI --other = %d, want -1", code)
	}
	// A NULL entry reads as "".
	withNULL := append(argv[:1:1], nil)
	if code := RHGMainCLI(2, &withNULL[0]); code != -1 {
		t.Fatalf("RHGMainCLI with a NULL argument = %d, want -1", code)
	}
}

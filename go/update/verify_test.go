package update

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeCall records one runCmd invocation.
type fakeCall struct {
	name    string
	args    []string
	timeout time.Duration
}

// fakeRunner replaces runCmd for one test. respond maps a tool path to its
// (stdout, error); unlisted tools fail. Returns the recorded calls.
func fakeRunner(t *testing.T, respond map[string]func(args []string) ([]byte, error)) *[]fakeCall {
	t.Helper()
	var calls []fakeCall
	orig := runCmd
	runCmd = func(timeout time.Duration, name string, args ...string) ([]byte, error) {
		calls = append(calls, fakeCall{name: name, args: slices.Clone(args), timeout: timeout})
		if f, ok := respond[name]; ok {
			return f(args)
		}
		return nil, errors.New("unexpected tool " + name)
	}
	t.Cleanup(func() { runCmd = orig })
	return &calls
}

func respondOK(out string) func(args []string) ([]byte, error) {
	return func([]string) ([]byte, error) { return []byte(out), nil }
}

func respondErr(msg string) func(args []string) ([]byte, error) {
	return func([]string) ([]byte, error) { return nil, errors.New(msg) }
}

// plutilKeys answers plutil -extract by key (args[1]); missing keys fail.
func plutilKeys(values map[string]string) func(args []string) ([]byte, error) {
	return func(args []string) ([]byte, error) {
		if v, ok := values[args[1]]; ok {
			return []byte(v + "\n"), nil
		}
		return nil, errors.New("No value at that key path")
	}
}

// execBundle creates a bundle in a temp dir whose Contents/MacOS/<exe> has
// mode perm, and returns the bundle path.
func execBundle(t *testing.T, exe string, perm os.FileMode) string {
	t.Helper()
	b := filepath.Join(t.TempDir(), testAppName)
	if err := os.MkdirAll(filepath.Join(b, "Contents", "MacOS"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b, "Contents", "MacOS", exe), []byte("x"), perm); err != nil {
		t.Fatal(err)
	}
	return b
}

const testBundle = "/Users/x/Library/Application Support/rhg-authenticator/update/staged-1.5.0.tmp/RHG Authenticator.app"

func TestCodesignVerify_Args(t *testing.T) {
	calls := fakeRunner(t, map[string]func(args []string) ([]byte, error){codesignPath: respondOK("")})
	if err := codesignVerify(testBundle, PinnedRequirement); err != nil {
		t.Fatal(err)
	}
	want := []fakeCall{{codesignPath, []string{"--verify", "--deep", "--strict", "-R=" + PinnedRequirement, testBundle}, codesignTimeout}}
	if !slices.EqualFunc(*calls, want, func(a, b fakeCall) bool {
		return a.name == b.name && slices.Equal(a.args, b.args) && a.timeout == b.timeout
	}) {
		t.Fatalf("calls = %+v, want %+v", *calls, want)
	}
}

func TestCodesignVerify_EmptyRequirement(t *testing.T) {
	calls := fakeRunner(t, map[string]func(args []string) ([]byte, error){codesignPath: respondOK("")})
	for _, req := range []string{"", "  \n"} {
		if err := codesignVerify(testBundle, req); err == nil {
			t.Fatalf("requirement %q accepted", req)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("codesign ran for an empty requirement: %+v", *calls)
	}
}

func TestCodesignVerify_Failure(t *testing.T) {
	fakeRunner(t, map[string]func(args []string) ([]byte, error){codesignPath: respondErr("test-requirement: code failed to satisfy")})
	err := codesignVerify(testBundle, PinnedRequirement)
	if err == nil || !strings.Contains(err.Error(), "failed to satisfy") {
		t.Fatalf("err = %v, want wrapped codesign failure", err)
	}
}

func TestPlistVersion(t *testing.T) {
	t.Run("args and trim", func(t *testing.T) {
		calls := fakeRunner(t, map[string]func(args []string) ([]byte, error){plutilPath: respondOK("1.5.0\n")})
		v, err := plistVersion(testBundle)
		if err != nil || v != "1.5.0" {
			t.Fatalf("plistVersion = %q, %v", v, err)
		}
		want := []string{"-extract", "CFBundleShortVersionString", "raw", "-o", "-", filepath.Join(testBundle, "Contents", "Info.plist")}
		if len(*calls) != 1 || (*calls)[0].name != plutilPath || !slices.Equal((*calls)[0].args, want) || (*calls)[0].timeout != plutilTimeout {
			t.Fatalf("calls = %+v, want plutil %q", *calls, want)
		}
	})
	t.Run("empty", func(t *testing.T) {
		fakeRunner(t, map[string]func(args []string) ([]byte, error){plutilPath: respondOK(" \n")})
		if _, err := plistVersion(testBundle); err == nil {
			t.Fatal("expected error for empty version")
		}
	})
	t.Run("tool failure", func(t *testing.T) {
		fakeRunner(t, map[string]func(args []string) ([]byte, error){plutilPath: respondErr("No value at that key path")})
		if _, err := plistVersion(testBundle); err == nil || !strings.Contains(err.Error(), "No value") {
			t.Fatalf("err = %v, want wrapped plutil failure", err)
		}
	})
}

func TestVerifyBundleTools(t *testing.T) {
	ok := plutilKeys(map[string]string{"CFBundleShortVersionString": "1.5.0", "CFBundleExecutable": "rhg-authenticator"})
	cases := []struct {
		name      string
		codesign  func(args []string) ([]byte, error)
		plutil    func(args []string) ([]byte, error)
		want      string
		wantErr   string // "" = success
		wantTools []string
	}{
		{"match", respondOK(""), ok, "v1.5.0", "", []string{codesignPath, plutilPath, plutilPath}},
		{"match two-part tag", respondOK(""), ok, "v1.5", "", []string{codesignPath, plutilPath, plutilPath}},
		{"version mismatch", respondOK(""), ok, "v1.6.0", "does not match", []string{codesignPath, plutilPath}},
		{"unparsable want", respondOK(""), ok, "dev", "does not match", []string{codesignPath, plutilPath}},
		{"signature fails first", respondErr("invalid signature"), ok, "v1.5.0", "invalid signature", []string{codesignPath}},
		{"plist unreadable", respondOK(""), respondErr("no plist"), "v1.5.0", "no plist", []string{codesignPath, plutilPath}},
		{"executable key missing", respondOK(""), plutilKeys(map[string]string{"CFBundleShortVersionString": "1.5.0"}),
			"v1.5.0", "CFBundleExecutable", []string{codesignPath, plutilPath, plutilPath}},
		{"executable name with path", respondOK(""), plutilKeys(map[string]string{"CFBundleShortVersionString": "1.5.0", "CFBundleExecutable": "../x"}),
			"v1.5.0", "not a plain file name", []string{codesignPath, plutilPath, plutilPath}},
		{"executable missing", respondOK(""), plutilKeys(map[string]string{"CFBundleShortVersionString": "1.5.0", "CFBundleExecutable": "other"}),
			"v1.5.0", "update bundle executable", []string{codesignPath, plutilPath, plutilPath}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantErr == "" && runtime.GOOS == "windows" {
				t.Skip("Windows file modes carry no exec bit")
			}
			bundle := execBundle(t, "rhg-authenticator", 0o755)
			calls := fakeRunner(t, map[string]func(args []string) ([]byte, error){codesignPath: tc.codesign, plutilPath: tc.plutil})
			err := verifyBundleTools(bundle, `identifier "x"`, tc.want)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("err = %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
			var tools []string
			for _, c := range *calls {
				tools = append(tools, c.name)
			}
			if !slices.Equal(tools, tc.wantTools) {
				t.Fatalf("tools = %q, want %q", tools, tc.wantTools)
			}
			if (*calls)[0].args[3] != `-R=identifier "x"` {
				t.Fatalf("requirement not passed through: %q", (*calls)[0].args)
			}
		})
	}
}

func TestCheckMainExecutable_Mode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	fakeRunner(t, map[string]func(args []string) ([]byte, error){
		plutilPath: plutilKeys(map[string]string{"CFBundleExecutable": "rhg-authenticator"}),
	})
	if err := checkMainExecutable(execBundle(t, "rhg-authenticator", 0o755)); err != nil {
		t.Fatalf("0755 rejected: %v", err)
	}
	if err := checkMainExecutable(execBundle(t, "rhg-authenticator", 0o644)); err == nil || !strings.Contains(err.Error(), "not an executable file") {
		t.Fatalf("0644 err = %v", err)
	}
	dirBundle := execBundle(t, "placeholder", 0o755)
	if err := os.Mkdir(filepath.Join(dirBundle, "Contents", "MacOS", "rhg-authenticator"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkMainExecutable(dirBundle); err == nil || !strings.Contains(err.Error(), "not an executable file") {
		t.Fatalf("directory err = %v", err)
	}

	// Contents/MacOS is a file: the bundle's own layout, so a rejection.
	flat := filepath.Join(t.TempDir(), testAppName)
	if err := os.MkdirAll(filepath.Join(flat, "Contents"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(flat, "Contents", "MacOS"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkMainExecutable(flat); err == nil || errors.Is(err, errTransient) {
		t.Fatalf("MacOS-is-a-file err = %v, want a non-transient error", err)
	}

	// Executable absent: the bundle's fault, a rejection.
	if err := checkMainExecutable(execBundle(t, "other", 0o755)); err == nil || errors.Is(err, errTransient) {
		t.Fatalf("missing executable err = %v, want a non-transient error", err)
	}

	// Unreadable directory: the machine's fault, transient.
	if os.Geteuid() != 0 {
		locked := execBundle(t, "rhg-authenticator", 0o755)
		macOS := filepath.Join(locked, "Contents", "MacOS")
		if err := os.Chmod(macOS, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(macOS, 0o755) })
		if err := checkMainExecutable(locked); !errors.Is(err, errTransient) {
			t.Fatalf("EACCES err = %v, want transient", err)
		}
	}
}

func TestPinnedVerifier_BindsRequirement(t *testing.T) {
	calls := fakeRunner(t, map[string]func(args []string) ([]byte, error){codesignPath: respondErr("stop")})
	if err := pinnedVerifier("REQ-X")(testBundle, "v1.5.0"); err == nil {
		t.Fatal("expected error")
	}
	if runtime.GOOS == "darwin" {
		if len(*calls) == 0 || (*calls)[0].args[3] != "-R=REQ-X" {
			t.Fatalf("requirement not bound: %+v", *calls)
		}
	} else if len(*calls) != 0 {
		t.Fatalf("tools ran off macOS: %+v", *calls)
	}
}

func TestRunCommand_Timeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	orig := toolWaitDelay
	toolWaitDelay = 100 * time.Millisecond
	t.Cleanup(func() { toolWaitDelay = orig })

	start := time.Now()
	// The background sleep inherits stdout; WaitDelay must still bound the wait.
	// sleep 10 outlives the 5s bound below, so the test fails if WaitDelay
	// stops bounding the wait for the inherited pipe.
	_, err = runCommand(200*time.Millisecond, sh, "-c", "sleep 10 & sleep 10")
	if !errors.Is(err, errTransient) {
		t.Fatalf("err = %v, want errTransient", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("runCommand returned after %s, want under 5s (WaitDelay must bound the inherited pipe)", d)
	}
}

func TestRunCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}

	out, err := runCommand(time.Minute, sh, "-c", "echo hello; echo noise >&2")
	if err != nil || string(out) != "hello\n" {
		t.Fatalf("success: out=%q err=%v (stdout only expected)", out, err)
	}

	_, err = runCommand(time.Minute, sh, "-c", "echo out; echo 'the reason' >&2; exit 3")
	if err == nil || !strings.Contains(err.Error(), "the reason") || !strings.Contains(err.Error(), "sh:") {
		t.Fatalf("failure err = %v, want tool name and stderr", err)
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 3 {
		t.Fatalf("err does not wrap ExitError(3): %v", err)
	}
	if errors.Is(err, errTransient) {
		t.Fatalf("a tool that exited with a status is a verdict, not transient: %v", err)
	}

	_, err = runCommand(time.Minute, sh, "-c", "exit 4")
	if err == nil || strings.HasSuffix(err.Error(), ": ") {
		t.Fatalf("silent failure err = %v", err)
	}

	if _, err := runCommand(time.Minute, "/nonexistent/tool"); err == nil || !strings.Contains(err.Error(), "tool:") || !errors.Is(err, errTransient) {
		t.Fatalf("missing tool err = %v, want transient", err)
	}

	// Killed by a signal: no verdict on the bundle.
	if _, err := runCommand(time.Minute, sh, "-c", "kill -TERM $$"); !errors.Is(err, errTransient) {
		t.Fatalf("signalled tool err = %v, want transient", err)
	}
}

func TestToolOutput(t *testing.T) {
	if got := toolOutput([]byte("  msg \n")); got != "msg" {
		t.Fatalf("toolOutput = %q", got)
	}
	long := strings.Repeat("x", maxToolOutputInError+10)
	got := toolOutput([]byte(long))
	if !strings.HasPrefix(got, strings.Repeat("x", maxToolOutputInError)) || !strings.HasSuffix(got, "…") ||
		len(got) != maxToolOutputInError+len("…") {
		t.Fatalf("toolOutput did not truncate: len %d", len(got))
	}
}

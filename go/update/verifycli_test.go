package update

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// cliRequirement records the requirement the last runVerifyCLI bound into
// its verifier ("" if none was built).
var cliRequirement string

// fixedVerifier returns a verifier constructor that ignores the requirement.
func fixedVerifier(v verifier) func(string) verifier {
	return func(string) verifier { return v }
}

// runVerifyCLI runs verifyZipCLI with verify and a fresh temp base, and
// returns the exit code, stdout, stderr and the temp base.
func runVerifyCLI(t *testing.T, args []string, verify verifier) (code int, stdout, stderr, base string) {
	t.Helper()
	base = t.TempDir()
	cliRequirement = ""
	var out, errOut bytes.Buffer
	code = verifyZipCLI(args, &out, &errOut, func(req string) verifier {
		cliRequirement = req
		return verify
	}, base)
	return code, out.String(), errOut.String(), base
}

// assertEmptyDir fails unless dir exists and is empty.
func assertEmptyDir(t *testing.T, dir string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	if len(ents) != 0 {
		t.Fatalf("%s not cleaned up: %d entries left (first %q)", dir, len(ents), ents[0].Name())
	}
}

func TestVerifyZipCLI_PassDefaultRequirement(t *testing.T) {
	zp := writeZip(t, bundle(testAppName))
	var bundleDir string
	verify, calls := recordingVerifier(nil, func(b string) { bundleDir = b })

	code, stdout, stderr, base := runVerifyCLI(t, []string{zp, "v1.5.0"}, verify)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, stderr)
	}
	if len(*calls) != 1 {
		t.Fatalf("verify called %d times", len(*calls))
	}
	c := (*calls)[0]
	if cliRequirement != PinnedRequirement {
		t.Errorf("requirement = %q, want PinnedRequirement", cliRequirement)
	}
	if c.version != "v1.5.0" {
		t.Errorf("version = %q", c.version)
	}
	if !strings.HasPrefix(bundleDir, base+string(filepath.Separator)) || filepath.Base(bundleDir) != testAppName {
		t.Errorf("bundle %q not staged under temp base %q", bundleDir, base)
	}
	if !strings.Contains(stdout, "OK") || stderr != "" {
		t.Errorf("stdout = %q, stderr = %q", stdout, stderr)
	}
	assertExists(t, zp)
	assertEmptyDir(t, base)
}

func TestVerifyZipCLI_RequirementOverride(t *testing.T) {
	zp := writeZip(t, bundle(testAppName))
	verify, calls := recordingVerifier(nil, nil)

	code, _, stderr, base := runVerifyCLI(t, []string{zp, "v0.0.0", "--requirement", "X"}, verify)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, stderr)
	}
	if len(*calls) != 1 || cliRequirement != "X" || (*calls)[0].version != "v0.0.0" {
		t.Fatalf("verify calls = %+v", *calls)
	}
	assertExists(t, zp)
	assertEmptyDir(t, base)
}

func TestVerifyZipCLI_VerificationFails(t *testing.T) {
	zp := writeZip(t, bundle(testAppName))
	verify, calls := recordingVerifier(errors.New("bad signature"), nil)

	code, stdout, stderr, base := runVerifyCLI(t, []string{zp, "v1.5.0"}, verify)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if len(*calls) != 1 {
		t.Fatalf("verify called %d times", len(*calls))
	}
	if stdout != "" || !strings.Contains(stderr, "FAIL") || !strings.Contains(stderr, "bad signature") {
		t.Errorf("stdout = %q, stderr = %q", stdout, stderr)
	}
	assertExists(t, zp)
	assertEmptyDir(t, base)
}

func TestVerifyZipCLI_BadArchiveFails(t *testing.T) {
	// A top-level __MACOSX entry fails scanZip before the verifier runs.
	zp := writeZip(t, append(bundle(testAppName), zipEntry{name: "__MACOSX/._x", body: "x"}))
	verify, calls := recordingVerifier(nil, nil)

	code, _, stderr, base := runVerifyCLI(t, []string{zp, "v1.5.0"}, verify)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr %q)", code, stderr)
	}
	if len(*calls) != 0 {
		t.Fatalf("verify ran on a rejected archive")
	}
	assertExists(t, zp)
	assertEmptyDir(t, base)
}

func TestVerifyZipCLI_MissingZipFails(t *testing.T) {
	verify, _ := recordingVerifier(nil, nil)
	code, _, _, base := runVerifyCLI(t, []string{filepath.Join(t.TempDir(), "nope.zip"), "v1.5.0"}, verify)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	assertEmptyDir(t, base)
}

func TestVerifyZipCLI_UsageErrors(t *testing.T) {
	zp := writeZip(t, bundle(testAppName))
	cases := map[string][]string{
		"no args":             nil,
		"one arg":             {zp},
		"three args":          {zp, "v1.5.0", "--requirement"},
		"five args":           {zp, "v1.5.0", "--requirement", "X", "Y"},
		"empty requirement":   {zp, "v1.5.0", "--requirement", ""},
		"unknown flag":        {zp, "v1.5.0", "--req", "X"},
		"flag first":          {"--requirement", "X", zp, "v1.5.0"},
		"empty zip path":      {"", "v1.5.0"},
		"unparsable tag":      {zp, "latest"},
		"empty tag":           {zp, ""},
		"tag with path chars": {zp, "v1.5/../0"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			verify, calls := recordingVerifier(nil, nil)
			code, stdout, stderr, base := runVerifyCLI(t, args, verify)
			if code != 2 {
				t.Fatalf("exit = %d, want 2", code)
			}
			if len(*calls) != 0 {
				t.Fatal("verifier ran on a usage error")
			}
			if stdout != "" || !strings.Contains(stderr, "usage:") {
				t.Errorf("stdout = %q, stderr = %q", stdout, stderr)
			}
			assertEmptyDir(t, base)
			assertExists(t, zp)
		})
	}
}

func TestVerifyZipCLI_TempDirCreateFails(t *testing.T) {
	zp := writeZip(t, bundle(testAppName))
	verify, calls := recordingVerifier(nil, nil)
	var out, errOut bytes.Buffer
	missing := filepath.Join(t.TempDir(), "missing")

	if code := verifyZipCLI([]string{zp, "v1.5.0"}, &out, &errOut, fixedVerifier(verify), missing); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if len(*calls) != 0 || !strings.Contains(errOut.String(), "temp dir") {
		t.Fatalf("calls = %d, stderr = %q", len(*calls), errOut.String())
	}
	assertExists(t, zp)
}

func TestVerifyZipCLI_TempDirRemoveFailsWarns(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX directory permissions enforced")
	}
	zp := writeZip(t, bundle(testAppName))
	base := t.TempDir()
	// Make the base read-only while the verifier runs, so the temp dir inside
	// it can be emptied but not unlinked.
	verify, _ := recordingVerifier(nil, func(string) {
		if err := os.Chmod(base, 0o500); err != nil {
			t.Fatal(err)
		}
	})
	t.Cleanup(func() { os.Chmod(base, 0o700) })
	var out, errOut bytes.Buffer

	if code := verifyZipCLI([]string{zp, "v1.5.0"}, &out, &errOut, fixedVerifier(verify), base); code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "warning: remove temp dir") {
		t.Fatalf("stderr = %q", errOut.String())
	}
}

func TestVerifyZipCLI_ExportedUsesRealVerifier(t *testing.T) {
	// Usage errors short-circuit before any verifier or filesystem access.
	var out, errOut bytes.Buffer
	if code := VerifyZipCLI(nil, &out, &errOut); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if runtime.GOOS == "darwin" {
		return
	}
	// Off macOS the production verifier is unsupported, so a well-formed zip
	// still fails verification.
	zp := writeZip(t, bundle(testAppName))
	out.Reset()
	errOut.Reset()
	if code := VerifyZipCLI([]string{zp, "v1.5.0"}, &out, &errOut); code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr %q)", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "unsupported") {
		t.Errorf("stderr = %q", errOut.String())
	}
	assertExists(t, zp)
}

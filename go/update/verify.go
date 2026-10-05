package update

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// System tools used to authenticate a bundle, by absolute path so $PATH can
// never substitute them.
const (
	codesignPath = "/usr/bin/codesign"
	plutilPath   = "/usr/bin/plutil"
)

// Tool deadlines. Apply runs on the quit path (including logout), so a
// stalled child must never keep the app from exiting. codesign --deep hashes
// the whole bundle; plutil reads one small file.
var (
	codesignTimeout = 2 * time.Minute
	plutilTimeout   = 10 * time.Second
	// toolWaitDelay bounds how long a killed tool may hold its output pipes.
	toolWaitDelay = 5 * time.Second
)

// maxToolOutputInError bounds how much tool output is quoted in an error.
const maxToolOutputInError = 512

// errTransient marks a failure of the local machine rather than of the
// release: a system tool that timed out or could not be started, or an I/O
// error reading the bundle. Neither stage nor apply records an apply-failed
// marker for it, so the update is retried on the next check.
var errTransient = errors.New("transient failure")

// verifier authenticates the bundle at bundlePath: its code signature must
// satisfy the requirement bound into the verifier, its sealed
// CFBundleShortVersionString must equal version (sameVersion), and its main
// executable must be an executable regular file.
type verifier func(bundlePath, version string) error

// pinnedVerifier returns the production verifier bound to requirement.
func pinnedVerifier(requirement string) verifier {
	return func(bundlePath, version string) error {
		return verifyBundle(bundlePath, requirement, version)
	}
}

// runCmd runs a system tool with an argument list (never a shell) under
// timeout and returns its stdout. A var so tests can substitute a fake.
var runCmd = runCommand

// runCommand executes name with args, killing it after timeout. On failure
// the error includes the tool's (trimmed, truncated) stderr for diagnosis;
// a deadline overrun, a tool that could not start, or one killed by a signal
// wraps errTransient; only a tool that exited with a status is a verdict.
func runCommand(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = toolWaitDelay
	out, err := cmd.Output()
	if err == nil {
		return out, nil
	}
	tool := filepath.Base(name)
	if ctx.Err() != nil {
		return out, fmt.Errorf("%s: %w: timed out after %s", tool, errTransient, timeout)
	}
	// No exit status (could not start) or killed by a signal (memory
	// pressure, logout tearing down the session): no verdict on the bundle.
	var ee *exec.ExitError
	if !errors.As(err, &ee) || !ee.Exited() {
		return out, fmt.Errorf("%s: %w: %w", tool, errTransient, err)
	}
	if msg := toolOutput(ee.Stderr); msg != "" {
		return out, fmt.Errorf("%s: %w: %s", tool, err, msg)
	}
	return out, fmt.Errorf("%s: %w", tool, err)
}

// toolOutput trims b and truncates it to maxToolOutputInError bytes.
func toolOutput(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > maxToolOutputInError {
		s = s[:maxToolOutputInError] + "…"
	}
	return s
}

// codesignVerify checks the bundle's signature (deep, strict) against
// requirement. "-R=<text>" is one argument: codesign reads the leading "=" of
// the option value as inline requirement text rather than a file path.
func codesignVerify(bundlePath, requirement string) error {
	if strings.TrimSpace(requirement) == "" {
		return errors.New("verify update bundle: empty code-signing requirement")
	}
	if _, err := runCmd(codesignTimeout, codesignPath, "--verify", "--deep", "--strict", "-R="+requirement, bundlePath); err != nil {
		return fmt.Errorf("verify update bundle signature: %w", err)
	}
	return nil
}

// plistString returns a top-level string key of the bundle's Info.plist.
// "-o -" is essential: without it plutil -extract overwrites the input file,
// which would break the bundle's signature seal.
func plistString(bundlePath, key string) (string, error) {
	plist := filepath.Join(bundlePath, "Contents", "Info.plist")
	out, err := runCmd(plutilTimeout, plutilPath, "-extract", key, "raw", "-o", "-", plist)
	if err != nil {
		return "", fmt.Errorf("read bundle %s: %w", key, err)
	}
	v := strings.TrimSpace(string(out))
	if v == "" {
		return "", fmt.Errorf("read bundle %s: empty value", key)
	}
	return v, nil
}

// plistVersion returns the bundle's CFBundleShortVersionString.
func plistVersion(bundlePath string) (string, error) {
	return plistString(bundlePath, "CFBundleShortVersionString")
}

// checkMainExecutable requires Contents/MacOS/<CFBundleExecutable> to be a
// regular file with an exec bit. codesign seals file contents, not POSIX
// modes, so a bundle that lost its exec bit would verify yet never launch.
func checkMainExecutable(bundlePath string) error {
	name, err := plistString(bundlePath, "CFBundleExecutable")
	if err != nil {
		return err
	}
	if name != filepath.Base(name) || name == "." || name == ".." {
		return fmt.Errorf("update bundle executable name %q is not a plain file name", name)
	}
	fi, err := os.Lstat(filepath.Join(bundlePath, "Contents", "MacOS", name))
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) { // bundle layout, not the machine
		return fmt.Errorf("update bundle executable: %w", err)
	}
	if err != nil {
		return fmt.Errorf("update bundle executable: %w: %w", errTransient, err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("update bundle executable %q is not an executable file (mode %s)", name, fi.Mode())
	}
	return nil
}

// verifyBundleTools is the platform-neutral body of verifyBundle: signature
// first (so nothing is trusted from an unauthenticated bundle), then the
// sealed plist version, then the main executable's mode.
func verifyBundleTools(bundlePath, requirement, version string) error {
	if err := codesignVerify(bundlePath, requirement); err != nil {
		return err
	}
	got, err := plistVersion(bundlePath)
	if err != nil {
		return err
	}
	if !sameVersion(got, version) {
		return fmt.Errorf("update bundle version %q does not match expected %q", got, version)
	}
	return checkMainExecutable(bundlePath)
}

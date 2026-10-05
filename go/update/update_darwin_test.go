//go:build darwin

package update

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// adHocRequirement is satisfied by an ad-hoc signature of the fixture bundle
// (no certificate), standing in for a release requirement in tests.
const adHocRequirement = `identifier "ge.royalhouseofgeorgia.rhg-authenticator"`

// requireTools fails unless the macOS signing tools are present. They ship
// with every macOS, so a skip could only hide a broken CI environment.
func requireTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{codesignPath, plutilPath, "/usr/bin/ditto", "/usr/bin/true"} {
		if _, err := os.Stat(tool); err != nil {
			t.Fatalf("%s not available: %v", tool, err)
		}
	}
}

// run executes a tool and fails the test with its output on error.
func run(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %q: %v\n%s", name, args, err, out)
	}
}

// buildBundle creates an ad-hoc signed "RHG Authenticator.app" under dir from
// the committed Info.plist, with CFBundleShortVersionString set the way the
// release workflow sets it (no "v").
func buildBundle(t *testing.T, dir, version string) string {
	t.Helper()
	b := filepath.Join(dir, testAppName)
	macOS := filepath.Join(b, "Contents", "MacOS")
	if err := os.MkdirAll(macOS, 0o755); err != nil {
		t.Fatal(err)
	}
	plist := filepath.Join(b, "Contents", "Info.plist")
	copyFile(t, "../packaging/macos/Info.plist", plist, 0o644)
	run(t, plutilPath, "-replace", "CFBundleShortVersionString", "-string", version, plist)
	copyFile(t, "/usr/bin/true", filepath.Join(macOS, "rhg-authenticator"), 0o755)
	run(t, codesignPath, "--force", "--sign", "-", b)
	return b
}

func copyFile(t *testing.T, src, dst string, perm os.FileMode) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

// zipBundle archives bundle exactly as the release workflow does.
func zipBundle(t *testing.T, bundle string) string {
	t.Helper()
	zp := filepath.Join(t.TempDir(), darwinAssetName)
	run(t, "/usr/bin/ditto", "-c", "-k", "--norsrc", "--noextattr", "--noqtn", "--keepParent", bundle, zp)
	return zp
}

func TestDarwin_VerifyBundle(t *testing.T) {
	requireTools(t)
	b := buildBundle(t, t.TempDir(), "1.5.0")

	if err := verifyBundle(b, adHocRequirement, "v1.5.0"); err != nil {
		t.Fatalf("ad-hoc requirement: %v", err)
	}
	if err := verifyBundle(b, PinnedRequirement, "v1.5.0"); err == nil {
		t.Fatal("PinnedRequirement accepted an ad-hoc signed bundle")
	}
	if err := verifyBundle(b, adHocRequirement, "v1.5.1"); err == nil {
		t.Fatal("wrong tag accepted")
	}
	if err := verifyBundle(b, `identifier "com.example.other"`, "v1.5.0"); err == nil {
		t.Fatal("wrong identifier accepted")
	}
}

func TestDarwin_BundleVersionLeavesSealIntact(t *testing.T) {
	requireTools(t)
	b := buildBundle(t, t.TempDir(), "1.5.0")
	plist := filepath.Join(b, "Contents", "Info.plist")
	before, err := os.ReadFile(plist)
	if err != nil {
		t.Fatal(err)
	}

	v, err := bundleVersion(b)
	if err != nil || v != "1.5.0" {
		t.Fatalf("bundleVersion = %q, %v", v, err)
	}

	after, err := os.ReadFile(plist)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("bundleVersion modified Info.plist")
	}
	if err := verifyBundle(b, adHocRequirement, "1.5.0"); err != nil {
		t.Fatalf("seal broken after bundleVersion: %v", err)
	}
}

func TestDarwin_VerifyBundle_Tampered(t *testing.T) {
	requireTools(t)
	b := buildBundle(t, t.TempDir(), "1.5.0")
	// Info.plist is bound into the code directory, so editing any key after
	// signing must break the seal regardless of the binary's layout.
	run(t, plutilPath, "-replace", "CFBundleName", "-string", "Tampered", filepath.Join(b, "Contents", "Info.plist"))
	err := verifyBundle(b, adHocRequirement, "1.5.0")
	if err == nil || !strings.Contains(err.Error(), "verify update bundle signature") {
		t.Fatalf("err = %v, want a signature failure", err)
	}
}

func TestDarwin_VerifyBundle_NotExecutable(t *testing.T) {
	requireTools(t)
	b := buildBundle(t, t.TempDir(), "1.5.0")
	// codesign seals contents, not modes: this bundle still has a valid
	// signature, and only the executable check stops it.
	if err := os.Chmod(filepath.Join(b, "Contents", "MacOS", "rhg-authenticator"), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, codesignPath, "--verify", "--deep", "--strict", b)
	err := verifyBundle(b, adHocRequirement, "1.5.0")
	if err == nil || !strings.Contains(err.Error(), "not an executable file") {
		t.Fatalf("err = %v, want executable check failure", err)
	}
}

func TestDarwin_StageRealZip(t *testing.T) {
	requireTools(t)
	zp := zipBundle(t, buildBundle(t, t.TempDir(), "1.5.0"))
	root := filepath.Join(t.TempDir(), "update")

	t.Run("pinned requirement rejects", func(t *testing.T) {
		dest := filepath.Join(root, "staged-1.5.0")
		if _, err := stage(zp, root, "v1.5.0", pinnedVerifier(PinnedRequirement)); !errors.Is(err, errBundleRejected) {
			t.Fatalf("err = %v, want errBundleRejected", err)
		}
		assertExists(t, zp)
		assertAbsent(t, dest)
		assertAbsent(t, dest+tmpSuffix)
	})

	t.Run("wrong tag rejects", func(t *testing.T) {
		dest := filepath.Join(root, "staged-1.5.1")
		if _, err := stage(zp, root, "v1.5.1", pinnedVerifier(adHocRequirement)); !errors.Is(err, errBundleRejected) {
			t.Fatalf("err = %v, want errBundleRejected", err)
		}
		assertExists(t, zp)
		assertAbsent(t, dest)
		assertAbsent(t, dest+tmpSuffix)
	})

	t.Run("success then ready", func(t *testing.T) {
		dest := filepath.Join(root, "staged-1.5.0")
		got, err := stage(zp, root, "v1.5.0", pinnedVerifier(adHocRequirement))
		if err != nil {
			t.Fatalf("stage: %v", err)
		}
		if got.App != filepath.Join(dest, testAppName) {
			t.Fatalf("staged = %+v", got)
		}
		fi, err := os.Stat(filepath.Join(got.App, "Contents", "MacOS", "rhg-authenticator"))
		if err != nil || fi.Mode().Perm()&0o111 == 0 {
			t.Fatalf("binary from the real ditto zip lost its exec bit: %v %v", fi, err)
		}
		assertExists(t, zp)
		assertAbsent(t, dest+tmpSuffix)

		d := defaultApplyDeps()
		d.verify = pinnedVerifier(adHocRequirement)
		ready, err := readyStaged(stagedBundle{Dir: dest, Version: "1.5.0"}, d)
		if err != nil || ready != got {
			t.Fatalf("readyStaged = %+v, %v", ready, err)
		}
	})
}

func TestDarwin_SwapBundles(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.app"), filepath.Join(dir, "b.app")
	for p, tag := range map[string]string{a: "A", b: "B"} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "id"), []byte(tag), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	read := func(p string) string {
		b, err := os.ReadFile(filepath.Join(p, "id"))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	if err := swapBundles(a, b); err != nil {
		t.Fatalf("swap: %v", err)
	}
	if read(a) != "B" || read(b) != "A" {
		t.Fatalf("after swap a=%s b=%s", read(a), read(b))
	}
	if err := swapBundles(a, b); err != nil {
		t.Fatalf("swap back: %v", err)
	}
	if read(a) != "A" || read(b) != "B" {
		t.Fatalf("after swap back a=%s b=%s", read(a), read(b))
	}
	if err := swapBundles(a, filepath.Join(dir, "missing.app")); err == nil {
		t.Fatal("swap with a missing entry succeeded")
	}
	if read(a) != "A" {
		t.Fatal("failed swap modified the source")
	}
}

func TestDarwin_ApplyRealSwap(t *testing.T) {
	requireTools(t)
	apps := filepath.Join(t.TempDir(), "Applications")
	if err := os.MkdirAll(apps, 0o755); err != nil {
		t.Fatal(err)
	}
	current := buildBundle(t, apps, "1.4.0")
	root := filepath.Join(t.TempDir(), "update")
	stagedDir := filepath.Join(root, "staged-1.5.0")
	if err := os.MkdirAll(stagedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	staged := buildBundle(t, stagedDir, "1.5.0")
	sb := stagedBundle{Dir: stagedDir, App: staged, Version: "1.5.0"}

	d := defaultApplyDeps()
	d.verify = pinnedVerifier(adHocRequirement)
	if err := apply(root, sb, current, "v1.4.0", d); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if v, _ := bundleVersion(current); v != "1.5.0" {
		t.Fatalf("current bundle is %q after apply, want 1.5.0", v)
	}
	if v, _ := bundleVersion(staged); v != "1.4.0" {
		t.Fatalf("staged dir holds %q after apply, want old 1.4.0", v)
	}

	// A second apply from the same (now swapped) state must not reverse it.
	err := apply(root, sb, current, "v1.4.0", d)
	if !errors.Is(err, errApplyGuard) {
		t.Fatalf("second apply err = %v, want errApplyGuard", err)
	}
	if v, _ := bundleVersion(current); v != "1.5.0" {
		t.Fatalf("second apply reversed the update: current is %q", v)
	}
	if isApplyFailed(root, "1.5.0") {
		t.Fatal("guard rejection wrote an apply-failed marker")
	}
}

func TestDarwin_Eligibility(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, testAppName)
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	home, _ := os.UserHomeDir()
	if ok, reason := eligible(bundle, home, accessWritable); ok || reason != reasonOutside {
		t.Fatalf("eligible(temp) = %v, %q; want outside-applications", ok, reason)
	}

	if err := accessWritable(dir); err != nil {
		t.Fatalf("temp dir not writable: %v", err)
	}
	if os.Geteuid() != 0 {
		ro := filepath.Join(dir, "ro")
		if err := os.Mkdir(ro, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(ro, 0o755) })
		if err := accessWritable(ro); err == nil {
			t.Fatal("read-only dir reported writable")
		}
	}

	// The test binary is not inside an .app bundle.
	if b, ok, reason := currentBundleEligible(); ok || b != "" || reason != reasonNotBundle {
		t.Fatalf("currentBundleEligible = %q, %v, %q", b, ok, reason)
	}
}

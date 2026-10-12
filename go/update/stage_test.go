package update

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

const testAppName = "RHG Authenticator.app"

// verifyCall records one verifier invocation.
type verifyCall struct{ bundle, version string }

// recordingVerifier returns a verifier that records its calls and returns err.
// If hook is non-nil it runs first (e.g. to inspect the extracted tree).
func recordingVerifier(err error, hook func(bundle string)) (verifier, *[]verifyCall) {
	var calls []verifyCall
	return func(bundle, version string) error {
		calls = append(calls, verifyCall{bundle, version})
		if hook != nil {
			hook(bundle)
		}
		return err
	}, &calls
}

// stageFixture returns a zip of a valid bundle, a fresh staging root, and the
// staged-1.5.0 directory stage will create in it.
func stageFixture(t *testing.T) (zipPath, root, dest string) {
	t.Helper()
	zipPath = writeZip(t, bundle(testAppName))
	root = filepath.Join(t.TempDir(), "update")
	return zipPath, root, filepath.Join(root, "staged-1.5.0")
}

// assertExists fails unless path exists.
func assertExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("%s should exist: %v", path, err)
	}
}

// assertAbsent fails if path exists.
func assertAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s should not exist (err=%v)", path, err)
	}
}

func TestStage_Success(t *testing.T) {
	zp, root, dest := stageFixture(t)
	var sawBin bool
	verify, calls := recordingVerifier(nil, func(b string) {
		_, err := os.Stat(filepath.Join(b, "Contents", "MacOS", "rhg-authenticator"))
		sawBin = err == nil
	})

	got, err := stage(zp, root, "v1.5.0", verify)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	want := stagedBundle{Dir: dest, App: filepath.Join(dest, testAppName), Version: "1.5.0"}
	if got != want {
		t.Fatalf("staged = %+v, want %+v", got, want)
	}
	if len(*calls) != 1 || (*calls)[0] != (verifyCall{filepath.Join(dest+tmpSuffix, testAppName), "v1.5.0"}) {
		t.Fatalf("verify calls = %+v", *calls)
	}
	if !sawBin {
		t.Fatal("bundle was not fully extracted when verify ran")
	}
	assertExists(t, filepath.Join(got.App, "Contents", "Info.plist"))
	assertAbsent(t, dest+tmpSuffix)
	assertExists(t, zp)
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(filepath.Join(got.App, "Contents", "MacOS", "rhg-authenticator"))
		if err != nil || fi.Mode().Perm()&0o100 == 0 {
			t.Fatalf("staged binary not executable: %v %v", fi, err)
		}
		r, err := os.Stat(root)
		if err != nil || r.Mode().Perm() != 0o700 {
			t.Fatalf("staging root mode = %v, %v; want 0700", r, err)
		}
	}
}

func TestStage_ReplacesStaleTmp(t *testing.T) {
	zp, root, dest := stageFixture(t)
	stale := filepath.Join(dest+tmpSuffix, "junk", "file")
	if err := os.MkdirAll(filepath.Dir(stale), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	verify, _ := recordingVerifier(nil, nil)
	if _, err := stage(zp, root, "v1.5.0", verify); err != nil {
		t.Fatalf("stage: %v", err)
	}
	assertAbsent(t, filepath.Join(dest, "junk"))
	assertAbsent(t, dest+tmpSuffix)
}

func TestStage_Failures(t *testing.T) {
	cases := []struct {
		name         string
		zip          func(t *testing.T) string
		verifyErr    error
		hook         func(dest string) func(string)
		wantErr      string
		wantRejected bool
		wantVerify   bool
	}{
		{name: "verify fails", verifyErr: errors.New("bad signature"),
			wantErr: "bad signature", wantRejected: true, wantVerify: true},
		{name: "verify transient", verifyErr: fmt.Errorf("codesign: %w: timed out", errTransient),
			wantErr: "timed out", wantVerify: true},
		{name: "executable missing", verifyErr: fmt.Errorf("update bundle executable: %w", os.ErrNotExist),
			wantErr: "executable", wantRejected: true, wantVerify: true},
		{name: "scan fails", zip: func(t *testing.T) string {
			return writeZip(t, []zipEntry{{name: "A.app/"}, {name: "B.app/"}})
		}, wantErr: "more than one top-level entry", wantRejected: true},
		{name: "duplicate entries", zip: func(t *testing.T) string {
			return writeZip(t, append(bundle(testAppName), zipEntry{name: testAppName + "/Contents/Info.plist", body: "x"}))
		}, wantErr: "duplicate entry", wantRejected: true},
		{name: "entry name too long", zip: func(t *testing.T) string {
			if runtime.GOOS == "windows" {
				t.Skip("Windows reports over-long names with its own error codes; the updater runs only on macOS")
			}
			return writeZip(t, append(bundle(testAppName), zipEntry{name: testAppName + "/" + strings.Repeat("a", 300), body: "x"}))
		}, wantErr: "file name too long", wantRejected: true},
		{name: "extract fails on lying size", zip: func(t *testing.T) string {
			return writeZip(t, []zipEntry{{name: "A.app/"}, {name: "A.app/lie", size: 1000}})
		}, wantErr: "extract", wantRejected: true},
		{name: "rename fails", hook: func(dest string) func(string) {
			// Something claims the staged dir between extraction and rename.
			return func(string) { os.MkdirAll(filepath.Join(dest, "occupied"), 0o700) }
		}, wantErr: "stage update", wantVerify: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			zp, root, dest := stageFixture(t)
			if tc.zip != nil {
				zp = tc.zip(t)
			}
			var hook func(string)
			if tc.hook != nil {
				hook = tc.hook(dest)
			}
			v, calls := recordingVerifier(tc.verifyErr, hook)
			_, err := stage(zp, root, "v1.5.0", v)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
			if errors.Is(err, errBundleRejected) != tc.wantRejected {
				t.Fatalf("rejected = %v, want %v (err %v)", errors.Is(err, errBundleRejected), tc.wantRejected, err)
			}
			if errors.Is(tc.verifyErr, errTransient) && !errors.Is(err, errTransient) {
				t.Fatalf("err %v lost errTransient", err)
			}
			if (len(*calls) > 0) != tc.wantVerify {
				t.Fatalf("verify calls = %d, wantVerify %v", len(*calls), tc.wantVerify)
			}
			assertExists(t, zp)
			assertAbsent(t, dest+tmpSuffix)
			if tc.hook == nil {
				assertAbsent(t, dest)
			}
		})
	}
}

func TestStage_InvalidVersion(t *testing.T) {
	zp, root, _ := stageFixture(t)
	verify, calls := recordingVerifier(nil, nil)
	if _, err := stage(zp, root, "dev", verify); err == nil || !strings.Contains(err.Error(), "invalid version") {
		t.Fatalf("err = %v", err)
	}
	if len(*calls) != 0 {
		t.Fatal("verify ran for an invalid version")
	}
}

func TestStage_DestExists(t *testing.T) {
	zp, root, dest := stageFixture(t)
	if err := os.MkdirAll(dest, 0o700); err != nil {
		t.Fatal(err)
	}
	verify, calls := recordingVerifier(nil, nil)
	if _, err := stage(zp, root, "v1.5.0", verify); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("err = %v, want already exists", err)
	}
	assertExists(t, dest)
	assertExists(t, zp)
	if len(*calls) != 0 {
		t.Fatal("verify ran despite existing staged dir")
	}
}

func TestStage_DestLstatError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ENOTDIR semantics differ on Windows")
	}
	zp, _, _ := stageFixture(t)
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	verify, _ := recordingVerifier(nil, nil)
	_, err := stage(zp, file, "v1.5.0", verify)
	if err == nil {
		t.Fatal("expected error when the staging root is a file")
	}
	if errors.Is(err, errBundleRejected) {
		t.Fatalf("local filesystem error classified as rejection: %v", err)
	}
	assertExists(t, zp)
}

func TestStage_FilesystemErrors(t *testing.T) {
	skipIfRoot(t)
	verify, _ := recordingVerifier(nil, nil)

	t.Run("stale tmp not removable", func(t *testing.T) {
		zp, root, dest := stageFixture(t)
		stuck := filepath.Join(dest+tmpSuffix, "sub")
		if err := os.MkdirAll(stuck, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(stuck, "f"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(stuck, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(stuck, 0o700) })
		if _, err := stage(zp, root, "v1.5.0", verify); err == nil || errors.Is(err, errBundleRejected) {
			t.Fatalf("err = %v, want non-rejection error", err)
		}
		assertExists(t, zp)
		assertAbsent(t, dest)
	})

	t.Run("root not creatable", func(t *testing.T) {
		zp := writeZip(t, bundle(testAppName))
		parent := t.TempDir()
		if err := os.Chmod(parent, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(parent, 0o700) })
		if _, err := stage(zp, filepath.Join(parent, "update"), "v1.5.0", verify); err == nil || errors.Is(err, errBundleRejected) {
			t.Fatalf("err = %v, want non-rejection error", err)
		}
		assertExists(t, zp)
	})

	t.Run("tmp not creatable", func(t *testing.T) {
		zp := writeZip(t, bundle(testAppName))
		root := t.TempDir()
		if err := os.Chmod(root, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(root, 0o700) })
		if _, err := stage(zp, root, "v1.5.0", verify); err == nil || errors.Is(err, errBundleRejected) {
			t.Fatalf("err = %v, want non-rejection error", err)
		}
		assertExists(t, zp)
	})
}

func TestIsArchiveRejection(t *testing.T) {
	if !isArchiveRejection(fmt.Errorf("x: %w", errArchiveTooLarge)) || !isArchiveRejection(errArchiveEntryType) {
		t.Fatal("archive sentinels not classified as rejection")
	}
	for _, errno := range []error{syscall.EEXIST, syscall.ENOTDIR, syscall.ENAMETOOLONG, errArchiveLayout} {
		if !isArchiveRejection(&fs.PathError{Op: "open", Path: "x", Err: errno}) {
			t.Fatalf("%v from a fresh extraction dir not classified as rejection", errno)
		}
	}
	if isArchiveRejection(&fs.PathError{Op: "open", Path: "x", Err: syscall.ENOSPC}) {
		t.Fatal("ENOSPC classified as rejection")
	}
	if isArchiveRejection(os.ErrPermission) {
		t.Fatal("local permission error classified as rejection")
	}
}

func TestIsArchiveRejection_CorruptDeflate(t *testing.T) {
	zp := writeZip(t, []zipEntry{{name: "A.app/"}, {name: "A.app/f", body: string(bytes.Repeat([]byte("abcdefgh"), 4096))}})
	b, err := os.ReadFile(zp)
	if err != nil {
		t.Fatal(err)
	}
	r, err := zip.OpenReader(zp)
	if err != nil {
		t.Fatal(err)
	}
	off, err := r.File[1].DataOffset()
	mid := int64(r.File[1].CompressedSize64 / 2)
	r.Close()
	if err != nil {
		t.Fatal(err)
	}
	// Flip bytes in the middle of the compressed stream (not a header, the
	// CRC, or the first block header, which would read as a short stream).
	b[off+mid] ^= 0xff
	b[off+mid+1] ^= 0xff
	if err := os.WriteFile(zp, b, 0o600); err != nil {
		t.Fatal(err)
	}
	err = extractZip(zp, t.TempDir())
	if !errors.As(err, new(flate.CorruptInputError)) || !isArchiveRejection(err) {
		t.Fatalf("corrupt deflate: err = %v (%T), rejection = %v", err, errors.Unwrap(err), isArchiveRejection(err))
	}
}

func TestStage_UnreadableZipNotRejected(t *testing.T) {
	verify, calls := recordingVerifier(nil, nil)
	_, err := stage(filepath.Join(t.TempDir(), "missing.zip"), t.TempDir(), "v1.5.0", verify)
	if err == nil || errors.Is(err, errBundleRejected) {
		t.Fatalf("err = %v, want a non-rejection error", err)
	}
	if len(*calls) != 0 {
		t.Fatal("verify ran for an unreadable zip")
	}
}

func TestStageInto_LocalExtractErrorNotRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	skipIfRoot(t)
	tmp := t.TempDir()
	if err := os.Chmod(tmp, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(tmp, 0o700) })
	verify, calls := recordingVerifier(nil, nil)
	err := stageInto(writeZip(t, bundle(testAppName)), tmp, testAppName, "v1.5.0", verify)
	if err == nil || errors.Is(err, errBundleRejected) {
		t.Fatalf("err = %v, want a non-rejection error", err)
	}
	if len(*calls) != 0 {
		t.Fatal("verify ran after a failed extraction")
	}
}

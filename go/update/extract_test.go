package update

import (
	"archive/zip"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// setMaxUncompressed lowers maxUncompressedBytes for one test.
func setMaxUncompressed(t *testing.T, n uint64) {
	t.Helper()
	orig := maxUncompressedBytes
	maxUncompressedBytes = n
	t.Cleanup(func() { maxUncompressedBytes = orig })
}

// skipIfRoot skips permission-based tests that root would bypass.
func skipIfRoot(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions not enforced on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses permission checks")
	}
}

func TestExtractZip_Bundle(t *testing.T) {
	const top = "RHG Authenticator.app"
	entries := append(bundle(top),
		zipEntry{name: top + "/Contents/Resources/deep/nested/file.txt", body: "hello"},
	)
	zp := writeZip(t, entries)
	dest := t.TempDir()

	if err := extractZip(zp, dest); err != nil {
		t.Fatalf("extractZip: %v", err)
	}

	b, err := os.ReadFile(filepath.Join(dest, top, "Contents", "Resources", "deep", "nested", "file.txt"))
	if err != nil || string(b) != "hello" {
		t.Fatalf("nested file = %q, %v", b, err)
	}
	b, err = os.ReadFile(filepath.Join(dest, top, "Contents", "Info.plist"))
	if err != nil || string(b) != "<plist/>" {
		t.Fatalf("Info.plist = %q, %v", b, err)
	}

	if runtime.GOOS == "windows" {
		return
	}
	bin, err := os.Stat(filepath.Join(dest, top, "Contents", "MacOS", "rhg-authenticator"))
	if err != nil {
		t.Fatal(err)
	}
	if bin.Mode().Perm() != 0o755 {
		t.Errorf("binary perm = %o, want 755 (exec bit preserved)", bin.Mode().Perm())
	}
	plist, err := os.Stat(filepath.Join(dest, top, "Contents", "Info.plist"))
	if err != nil {
		t.Fatal(err)
	}
	if plist.Mode().Perm() != 0o644 {
		t.Errorf("plist perm = %o, want 644", plist.Mode().Perm())
	}
	dir, err := os.Stat(filepath.Join(dest, top, "Contents", "Resources", "deep"))
	if err != nil {
		t.Fatal(err)
	}
	if !dir.IsDir() || dir.Mode().Perm() != 0o755 {
		t.Errorf("implicit dir mode = %v, want dir 755", dir.Mode())
	}
}

func TestExtractZip_PermBitsClampedDespiteUmask(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions not enforced on Windows")
	}
	zp := writeZip(t, []zipEntry{
		{name: "A.app/"},
		{name: "A.app/x", mode: 0o777, body: "x"},
		{name: "A.app/ro", mode: 0o444, body: "ro"},
		{name: "A.app/ww", mode: 0o666, body: "ww"},
	})
	dest := t.TempDir()
	if err := extractZip(zp, dest); err != nil {
		t.Fatal(err)
	}
	// Archive modes are untrusted (codesign does not seal them): only the
	// exec bit survives, and nothing is ever group/other-writable.
	for name, want := range map[string]fs.FileMode{"x": 0o755, "ro": 0o644, "ww": 0o644} {
		fi, err := os.Stat(filepath.Join(dest, "A.app", name))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s perm = %o, want %o", name, fi.Mode().Perm(), want)
		}
	}
}

func TestExtractZip_ByteCap(t *testing.T) {
	entries := []zipEntry{
		{name: "A.app/"},
		{name: "A.app/a", body: strings.Repeat("a", 60)},
		{name: "A.app/b", body: strings.Repeat("b", 40)},
	}

	t.Run("at cap", func(t *testing.T) {
		setMaxUncompressed(t, 100)
		if err := extractZip(writeZip(t, entries), t.TempDir()); err != nil {
			t.Fatalf("100 bytes at cap 100: %v", err)
		}
	})
	t.Run("over cap across entries", func(t *testing.T) {
		setMaxUncompressed(t, 99)
		err := extractZip(writeZip(t, entries), t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "more than 99 bytes") {
			t.Fatalf("err = %v, want byte-cap error", err)
		}
	})
}

func TestExtractZip_DeclaredSizeLie(t *testing.T) {
	// Declares 1000 bytes but stores none: archive/zip must fail the read.
	zp := writeZip(t, []zipEntry{
		{name: "A.app/"},
		{name: "A.app/lie", size: 1000},
	})
	if err := extractZip(zp, t.TempDir()); err == nil {
		t.Fatal("expected error for entry whose content does not match its declared size")
	}
}

func TestExtractZip_RefusesExistingPaths(t *testing.T) {
	zp := writeZip(t, bundle("A.app"))

	t.Run("pre-existing file", func(t *testing.T) {
		dest := t.TempDir()
		target := filepath.Join(dest, "A.app", "Contents", "Info.plist")
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte("original"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := extractZip(zp, dest); err == nil {
			t.Fatal("expected error for pre-existing file")
		}
		if b, _ := os.ReadFile(target); string(b) != "original" {
			t.Fatalf("pre-existing file overwritten: %q", b)
		}
	})

	t.Run("symlink at target", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlinks need privileges on Windows")
		}
		dest := t.TempDir()
		outside := filepath.Join(t.TempDir(), "victim")
		if err := os.WriteFile(outside, []byte("victim"), 0o644); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(dest, "A.app", "Contents", "Info.plist")
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, target); err != nil {
			t.Fatal(err)
		}
		if err := extractZip(zp, dest); err == nil {
			t.Fatal("expected error for symlink at target")
		}
		if b, _ := os.ReadFile(outside); string(b) != "victim" {
			t.Fatalf("write followed symlink: victim = %q", b)
		}
	})

	t.Run("dangling symlink at target", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlinks need privileges on Windows")
		}
		dest := t.TempDir()
		outside := filepath.Join(t.TempDir(), "created-by-attacker")
		target := filepath.Join(dest, "A.app", "Contents", "Info.plist")
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, target); err != nil {
			t.Fatal(err)
		}
		if err := extractZip(zp, dest); err == nil {
			t.Fatal("expected error for dangling symlink at target")
		}
		if _, err := os.Lstat(outside); err == nil {
			t.Fatal("extraction created a file through a dangling symlink")
		}
	})

	t.Run("duplicate entry", func(t *testing.T) {
		dup := writeZip(t, []zipEntry{
			{name: "A.app/"},
			{name: "A.app/x", body: "1"},
			{name: "A.app/x", body: "2"},
		})
		if err := extractZip(dup, t.TempDir()); err == nil {
			t.Fatal("expected error for duplicate entry")
		}
	})

	t.Run("file where dir entry goes", func(t *testing.T) {
		dest := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dest, "A.app"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dest, "A.app", "Contents"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := extractZip(zp, dest); err == nil {
			t.Fatal("expected error when a dir entry collides with a file")
		}
	})

	t.Run("file where parent dir goes", func(t *testing.T) {
		// No explicit dir entries, so the parent is created implicitly.
		zp := writeZip(t, []zipEntry{{name: "A.app/Contents/Info.plist", body: "x"}})
		dest := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dest, "A.app"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dest, "A.app", "Contents"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := extractZip(zp, dest); err == nil {
			t.Fatal("expected error when a parent dir collides with a file")
		}
	})
}

func TestExtractZip_RevalidatesEntries(t *testing.T) {
	cases := map[string][]zipEntry{
		"traversal": {{name: "A.app/"}, {name: "A.app/../../evil", body: "x"}},
		"absolute":  {{name: "/A.app/x", body: "x"}},
		"symlink":   {{name: "A.app/"}, {name: "A.app/link", mode: fs.ModeSymlink | 0o777, body: "/etc/passwd"}},
		"device":    {{name: "A.app/"}, {name: "A.app/dev", mode: fs.ModeDevice | 0o644}},
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			dest := t.TempDir()
			if err := extractZip(writeZip(t, entries), dest); err == nil {
				t.Fatal("expected error")
			}
			if _, err := os.Lstat(filepath.Join(dest, "A.app", "link")); err == nil {
				t.Fatal("symlink was created")
			}
		})
	}
}

func TestExtractZip_UnsupportedCompression(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	if _, err := zw.CreateHeader(&zip.FileHeader{Name: "A.app/"}); err != nil {
		t.Fatal(err)
	}
	hdr := &zip.FileHeader{Name: "A.app/x", Method: 99}
	hdr.SetMode(0o644)
	if _, err := zw.CreateRaw(hdr); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := extractZip(path, t.TempDir()); err == nil {
		t.Fatal("expected error for unsupported compression method")
	}
}

func TestExtractZip_OpenErrors(t *testing.T) {
	if err := extractZip(filepath.Join(t.TempDir(), "missing.zip"), t.TempDir()); err == nil {
		t.Fatal("expected error for missing archive")
	}
	notZip := filepath.Join(t.TempDir(), "x.zip")
	if err := os.WriteFile(notZip, []byte("not a zip"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := extractZip(notZip, t.TempDir()); err == nil {
		t.Fatal("expected error for non-zip file")
	}
}

func TestExtractZip_InsecurePathGodebug(t *testing.T) {
	// With zipinsecurepath=0 the reader itself fails (and returns a non-nil
	// reader that must be closed).
	t.Setenv("GODEBUG", "zipinsecurepath=0")
	dest := t.TempDir()
	if err := extractZip(writeZip(t, []zipEntry{{name: "../evil", body: "x"}}), dest); err == nil {
		t.Fatal("expected rejection")
	}
	assertAbsent(t, filepath.Join(filepath.Dir(dest), "evil"))
}

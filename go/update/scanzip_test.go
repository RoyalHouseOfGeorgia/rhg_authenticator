package update

import (
	"archive/zip"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// zipEntry describes one entry to write into a test archive.
type zipEntry struct {
	name string
	mode fs.FileMode // 0 means a regular 0o644 file (or 0o755 dir if name ends in "/")
	body string
	size uint64 // if non-zero, overrides the declared UncompressedSize64
}

// writeZip builds an archive from entries in a temp dir and returns its path.
func writeZip(t *testing.T, entries []zipEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for _, e := range entries {
		if e.size != 0 {
			// Raw entry so the declared size can differ from the content,
			// mimicking a crafted header without writing hundreds of MB.
			hdr := &zip.FileHeader{Name: e.name, Method: zip.Store, UncompressedSize64: e.size, CompressedSize64: 0}
			hdr.SetMode(0o644)
			if _, err := zw.CreateRaw(hdr); err != nil {
				t.Fatal(err)
			}
			continue
		}
		hdr := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		switch {
		case e.mode != 0:
			hdr.SetMode(e.mode)
		case len(e.name) > 0 && e.name[len(e.name)-1] == '/':
			hdr.SetMode(fs.ModeDir | 0o755)
		default:
			hdr.SetMode(0o644)
		}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// bundle returns a minimal valid bundle layout under top.
func bundle(top string) []zipEntry {
	return []zipEntry{
		{name: top + "/"},
		{name: top + "/Contents/"},
		{name: top + "/Contents/Info.plist", body: "<plist/>"},
		{name: top + "/Contents/MacOS/"},
		{name: top + "/Contents/MacOS/rhg-authenticator", mode: 0o755, body: "\xcf\xfa\xed\xfe"},
	}
}

func TestScanZip_Valid(t *testing.T) {
	cases := []struct {
		name    string
		entries []zipEntry
		want    string
	}{
		{"space in name", bundle("RHG Authenticator.app"), "RHG Authenticator.app"},
		{"no space", bundle("Foo.app"), "Foo.app"},
		// ditto omits explicit directory entries in some modes.
		{"no dir entries", []zipEntry{
			{name: "RHG Authenticator.app/Contents/Info.plist", body: "x"},
			{name: "RHG Authenticator.app/Contents/MacOS/bin", body: "y"},
		}, "RHG Authenticator.app"},
		{"nested dot-underscore inside bundle", append(bundle("A.app"),
			zipEntry{name: "A.app/Contents/._Info.plist", body: "x"}), "A.app"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := scanZip(writeZip(t, tc.entries))
			if err != nil {
				t.Fatalf("scanZip: %v", err)
			}
			if got != tc.want {
				t.Fatalf("scanZip = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestScanZip_Rejects(t *testing.T) {
	const top = "RHG Authenticator.app"
	with := func(extra ...zipEntry) []zipEntry { return append(bundle(top), extra...) }
	cases := []struct {
		name    string
		entries []zipEntry
		wantErr string
	}{
		{"dotdot traversal", with(zipEntry{name: top + "/../../evil", body: "x"}), "not a safe relative path"},
		{"leading dotdot", []zipEntry{{name: "../" + top + "/x", body: "x"}}, "not a safe relative path"},
		{"dotdot only", []zipEntry{{name: ".."}}, "not a safe relative path"},
		{"dot segment", with(zipEntry{name: top + "/./x", body: "x"}), "not a safe relative path"},
		{"absolute", with(zipEntry{name: "/" + top + "/x", body: "x"}), "not a safe relative path"},
		{"absolute first", []zipEntry{{name: "/etc/passwd", body: "x"}}, "not a safe relative path"},
		{"backslash", with(zipEntry{name: top + "\\..\\evil", body: "x"}), "not a safe relative path"},
		{"backslash top", []zipEntry{{name: "A.app\\x", body: "x"}}, "not a safe relative path"},
		{"empty segment", with(zipEntry{name: top + "//x", body: "x"}), "not a safe relative path"},
		{"dotdot inside a name", with(zipEntry{name: top + "/foo..bar", body: "x"}), "not a safe relative path"},
		{"newline", with(zipEntry{name: top + "/x\ny", body: "x"}), "not a safe relative path"},
		{"DEL", with(zipEntry{name: top + "/x\x7fy", body: "x"}), "not a safe relative path"},
		{"nul byte", with(zipEntry{name: top + "/x\x00y", body: "x"}), "not a safe relative path"},
		{"empty name", []zipEntry{{name: "", body: "x"}}, "not a safe relative path"},
		{"slash only", []zipEntry{{name: "/"}}, "not a safe relative path"},
		{"symlink", with(zipEntry{name: top + "/Contents/link", mode: fs.ModeSymlink | 0o777, body: "/etc"}), "is a symlink"},
		{"symlink top", []zipEntry{{name: top, mode: fs.ModeSymlink | 0o777, body: "/tmp"}}, "is a symlink"},
		{"named pipe", with(zipEntry{name: top + "/fifo", mode: fs.ModeNamedPipe | 0o644}), "not a regular file or directory"},
		{"device", with(zipEntry{name: top + "/dev", mode: fs.ModeDevice | 0o644}), "not a regular file or directory"},
		{"two top-level", with(zipEntry{name: "Other.app/x", body: "x"}), "more than one top-level entry"},
		{"top-level file", with(zipEntry{name: "README", body: "x"}), "more than one top-level entry"},
		{"__MACOSX", with(zipEntry{name: "__MACOSX/"}, zipEntry{name: "__MACOSX/._x", body: "x"}), "more than one top-level entry"},
		{"__MACOSX first", append([]zipEntry{{name: "__MACOSX/._x", body: "x"}}, bundle(top)...), "is not an .app bundle"},
		{"dot-underscore top", with(zipEntry{name: "._" + top, body: "x"}), "more than one top-level entry"},
		{"non-.app top", bundle("RHG Authenticator"), "is not an .app bundle"},
		{".app.zip top", bundle("Foo.app.zip"), "is not an .app bundle"},
		{"bare .app", bundle(".app"), "is not an .app bundle"},
		{"hidden .app", bundle("._Foo.app"), "is not an .app bundle"},
		{"top is a file", []zipEntry{{name: top, body: "x"}}, "is not a directory"},
		{"duplicate file", with(zipEntry{name: top + "/Contents/Info.plist", body: "x"}), "duplicate entry"},
		{"duplicate dir", with(zipEntry{name: top + "/"}), "duplicate entry"},
		{"file then child", with(zipEntry{name: top + "/f", body: "x"}, zipEntry{name: top + "/f/g", body: "x"}), "both a file and a directory"},
		{"child then file", with(zipEntry{name: top + "/f/g", body: "x"}, zipEntry{name: top + "/f", body: "x"}), "both a file and a directory"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := scanZip(writeZip(t, tc.entries))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %q, err = %v; want error containing %q", got, err, tc.wantErr)
			}
		})
	}
}

func TestScanZip_UncompressedCap(t *testing.T) {
	orig := maxUncompressedBytes
	maxUncompressedBytes = 1000
	t.Cleanup(func() { maxUncompressedBytes = orig })

	const top = "A.app"
	t.Run("at cap", func(t *testing.T) {
		entries := []zipEntry{{name: top + "/a", size: 600}, {name: top + "/b", size: 400}}
		if _, err := scanZip(writeZip(t, entries)); err != nil {
			t.Fatalf("expected success at cap: %v", err)
		}
	})
	t.Run("over cap single", func(t *testing.T) {
		entries := []zipEntry{{name: top + "/a", size: 1001}}
		if _, err := scanZip(writeZip(t, entries)); err == nil {
			t.Fatal("expected rejection over cap")
		}
	})
	t.Run("over cap sum", func(t *testing.T) {
		entries := []zipEntry{{name: top + "/a", size: 600}, {name: top + "/b", size: 401}}
		if _, err := scanZip(writeZip(t, entries)); err == nil {
			t.Fatal("expected rejection when sum exceeds cap")
		}
	})
	t.Run("overflow", func(t *testing.T) {
		entries := []zipEntry{{name: top + "/a", size: 500}, {name: top + "/b", size: ^uint64(0) - 100}}
		if _, err := scanZip(writeZip(t, entries)); err == nil {
			t.Fatal("expected rejection on size overflow")
		}
	})
}

func TestScanZip_DefaultCap(t *testing.T) {
	// A declared entry one byte over the production cap is rejected.
	entries := []zipEntry{{name: "A.app/big", size: maxUncompressedBytes + 1}}
	if _, err := scanZip(writeZip(t, entries)); !errors.Is(err, errArchiveTooLarge) {
		t.Fatalf("err = %v, want errArchiveTooLarge", err)
	}
}

func TestScanZip_Empty(t *testing.T) {
	if _, err := scanZip(writeZip(t, nil)); err == nil {
		t.Fatal("expected rejection of empty archive")
	}
}

func TestScanZip_NotAZip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.zip")
	if err := os.WriteFile(path, []byte("this is not a zip archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := scanZip(path); err == nil {
		t.Fatal("expected error for non-zip file")
	}
}

func TestScanZip_Missing(t *testing.T) {
	if _, err := scanZip(filepath.Join(t.TempDir(), "missing.zip")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

// TestScanZip_InsecurePathGodebug: with zipinsecurepath=0 the stdlib reader
// itself flags the archive (returning a usable reader plus ErrInsecurePath);
// scanZip must still reject it and not leak the open file.
func TestScanZip_InsecurePathGodebug(t *testing.T) {
	t.Setenv("GODEBUG", "zipinsecurepath=0")
	if _, err := scanZip(writeZip(t, []zipEntry{{name: "../evil", body: "x"}})); err == nil {
		t.Fatal("expected rejection")
	}
}

func TestScanZip_EntryCountCapped(t *testing.T) {
	orig := maxZipEntries
	maxZipEntries = 8
	t.Cleanup(func() { maxZipEntries = orig })
	entries := func(n int) []zipEntry {
		es := []zipEntry{{name: "X.app/"}}
		for i := 1; i < n; i++ {
			es = append(es, zipEntry{name: fmt.Sprintf("X.app/f%d", i)})
		}
		return es
	}
	if _, err := scanZip(writeZip(t, entries(maxZipEntries))); err != nil {
		t.Fatalf("archive at the entry cap rejected: %v", err)
	}
	if _, err := scanZip(writeZip(t, entries(maxZipEntries+1))); !errors.Is(err, errArchiveTooLarge) {
		t.Fatalf("err = %v, want errArchiveTooLarge", err)
	}
}

package service

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/bulk"
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
)

// exportRecords is an issuance log with one record.
const exportRecords = `[{"recipient":"x"}]`

// noTempFiles fails t if dir holds a leftover export temp file.
func noTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".rhg-save-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

// readFile returns path's contents, failing t on error.
func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestExportIssuanceLog_OverwritesTarget(t *testing.T) {
	h := newAppHarness(t, nil)
	writeRawLog(t, h, exportRecords)
	out := t.TempDir()
	target := filepath.Join(out, "export.json")
	if err := os.WriteFile(target, []byte("old contents that are longer"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := h.app.ExportIssuanceLog(target); err != nil {
		t.Fatalf("ExportIssuanceLog: %v", err)
	}
	if got := readFile(t, target); got != exportRecords {
		t.Errorf("target = %q, want %q", got, exportRecords)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != exportFileMode {
			t.Errorf("mode = %v, want %v", info.Mode().Perm(), os.FileMode(exportFileMode))
		}
	}
	noTempFiles(t, out)
}

func TestExportErrorLog_NewTarget(t *testing.T) {
	h := newAppHarness(t, nil)
	h.app.logger.Log("hello diagnostics")
	target := filepath.Join(t.TempDir(), "errors.log")
	if err := h.app.ExportErrorLog(target); err != nil {
		t.Fatalf("ExportErrorLog: %v", err)
	}
	if got := readFile(t, target); !strings.Contains(got, "hello diagnostics") {
		t.Errorf("target = %q", got)
	}
}

func TestExportIssuanceLog_NothingToExport(t *testing.T) {
	for _, content := range []string{"", "[]\n"} { // "" = no log file
		t.Run(fmt.Sprintf("%q", content), func(t *testing.T) {
			h := newAppHarness(t, nil)
			if content != "" {
				writeRawLog(t, h, content)
			}
			target := filepath.Join(t.TempDir(), "export.json")
			if err := h.app.ExportIssuanceLog(target); !errors.Is(err, ErrNothingToExport) {
				t.Fatalf("err = %v, want ErrNothingToExport", err)
			}
			if _, err := os.Stat(target); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("target created: %v", err)
			}
		})
	}
}

func TestExportErrorLog_ReadError(t *testing.T) {
	h := newAppHarness(t, nil)
	h.app.logger = debuglog.New(filepath.Join(h.dir, "absent.log"))
	target := filepath.Join(t.TempDir(), "errors.log")
	if err := h.app.ExportErrorLog(target); err == nil || err.Error() != "Could not read the error log." {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(target); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("target created: %v", err)
	}
}

func TestExport_MissingFolder(t *testing.T) {
	h := newAppHarness(t, nil)
	writeRawLog(t, h, exportRecords)
	target := filepath.Join(t.TempDir(), "absent", "export.json")
	err := h.app.ExportIssuanceLog(target)
	if err == nil || err.Error() != msgSaveNoFolder || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v, want %q wrapping fs.ErrNotExist", err, msgSaveNoFolder)
	}
	if !strings.Contains(h.debugLog(t), "save failed: ") {
		t.Error("save failure not logged")
	}
}

func TestExport_UnwritableFolder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permission bits don't restrict writes on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	h := newAppHarness(t, nil)
	writeRawLog(t, h, exportRecords)
	out := t.TempDir()
	if err := os.Chmod(out, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(out, 0o700) })
	err := h.app.ExportIssuanceLog(filepath.Join(out, "export.json"))
	if err == nil || err.Error() != msgSavePermission || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("err = %v, want %q wrapping fs.ErrPermission", err, msgSavePermission)
	}
	noTempFiles(t, out)
}

func TestExport_RenameFailureRemovesTemp(t *testing.T) {
	h := newAppHarness(t, nil)
	writeRawLog(t, h, exportRecords)
	out := t.TempDir()
	target := filepath.Join(out, "export.json")
	// A non-empty directory at the target makes the final rename fail.
	if err := os.MkdirAll(filepath.Join(target, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	// The text depends on the platform (Windows reports access denied).
	err := h.app.ExportIssuanceLog(target)
	if err == nil || (err.Error() != msgSaveFailed && err.Error() != msgSavePermission) {
		t.Fatalf("err = %v, want a save failure", err)
	}
	noTempFiles(t, out)
}

// caseInsensitive reports whether dir is on a case-insensitive filesystem.
func caseInsensitive(t *testing.T, dir string) bool {
	t.Helper()
	probe := filepath.Join(dir, "case-probe")
	if err := os.WriteFile(probe, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(probe)
	_, err := os.Stat(filepath.Join(dir, "CASE-PROBE"))
	return err == nil
}

// mustCover fails t on macOS and Windows, where the shipped app runs and the
// variant must be tested, and logs the skip elsewhere.
func mustCover(t *testing.T, ok bool, what string) {
	t.Helper()
	if ok {
		return
	}
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		t.Fatalf("%s variant not tested on %s", what, runtime.GOOS)
	}
	t.Logf("%s variant skipped on %s", what, runtime.GOOS)
}

func TestSave_RefusesDataFolder(t *testing.T) {
	h := newAppHarness(t, nil)
	dir := h.dir
	writeRawLog(t, h, exportRecords)
	h.app.logger.Log("diagnostics")
	backup := h.app.logPath + ".bak-20260101T000000Z"
	if err := os.WriteFile(backup, []byte("backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(t.TempDir(), "datadir")
	symlinks := os.Symlink(dir, linkDir) == nil
	foldsCase := caseInsensitive(t, dir)
	mustCover(t, foldsCase, "case")
	if runtime.GOOS == "windows" {
		mustCover(t, symlinks, "symlinked folder")
	}

	saves := map[string]func(string) error{
		"issuance": h.app.ExportIssuanceLog,
		"error":    h.app.ExportErrorLog,
		"qr":       func(p string) error { return h.app.SaveQR("https://example.org/v", "svg", p) },
	}
	// A new file in the data folder is refused as well as the logs.
	for _, protected := range []string{h.app.logPath, backup, h.app.logger.Path(), filepath.Join(dir, "new.txt")} {
		base := filepath.Base(protected)
		variants := map[string]string{
			"exact":  protected,
			"dotdot": filepath.Join(dir, "sub") + string(filepath.Separator) + ".." + string(filepath.Separator) + base,
		}
		if symlinks {
			variants["symlinked dir"] = filepath.Join(linkDir, base)
		}
		if foldsCase {
			variants["case"] = filepath.Join(strings.ToUpper(dir), base)
		}
		for vname, target := range variants {
			for sname, save := range saves {
				t.Run(base+"/"+vname+"/"+sname, func(t *testing.T) {
					before, _ := os.ReadFile(protected)
					if err := save(target); !errors.Is(err, ErrProtectedPath) {
						t.Fatalf("err = %v, want ErrProtectedPath", err)
					}
					// The refusal itself is logged to the debug log, so
					// that file legitimately grows; the others must not change.
					after, _ := os.ReadFile(protected)
					if protected == h.app.logger.Path() {
						if !strings.HasPrefix(string(after), string(before)) {
							t.Errorf("debug log rewritten: %q -> %q", before, after)
						}
					} else if string(after) != string(before) {
						t.Errorf("protected file changed: %q -> %q", before, after)
					}
					noTempFiles(t, dir)
				})
			}
		}
	}
	if !strings.Contains(h.debugLog(t), "save refused in the data folder: ") {
		t.Error("refusal not logged")
	}
}

func TestSave_BulkResultsRefusesDataFolder(t *testing.T) {
	h := newAppHarness(t, nil)
	h.app.plan = []bulk.Result{{Status: bulk.StatusSigned}}
	if err := h.app.ExportBulkResults(filepath.Join(h.dir, "r.csv")); !errors.Is(err, ErrProtectedPath) {
		t.Fatalf("err = %v, want ErrProtectedPath", err)
	}
}

// TestSave_SymlinkToLogReplacesLink checks that saving onto a symlink outside
// the data folder that points at a log replaces the link and leaves the log.
func TestSave_SymlinkToLogReplacesLink(t *testing.T) {
	h := newAppHarness(t, nil)
	writeRawLog(t, h, exportRecords)
	h.app.logger.Log("diagnostics")
	link := filepath.Join(t.TempDir(), "link.json")
	if err := os.Symlink(h.app.logPath, link); err != nil {
		mustCover(t, runtime.GOOS != "windows", "symlink")
		t.Skip("symlinks unavailable")
	}
	if err := h.app.ExportErrorLog(link); err != nil {
		t.Fatalf("ExportErrorLog: %v", err)
	}
	if got := readFile(t, h.app.logPath); got != exportRecords {
		t.Errorf("issuance log changed: %q", got)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&fs.ModeSymlink != 0 {
		t.Errorf("link not replaced by a file: %v %v", info, err)
	}
}

func TestSave_RelativePathRefused(t *testing.T) {
	h := newAppHarness(t, nil)
	writeRawLog(t, h, exportRecords)
	for _, p := range []string{"", "export.json", filepath.Join("sub", "export.json")} {
		if err := h.app.ExportIssuanceLog(p); err == nil || err.Error() != "Choose a file to save to." {
			t.Errorf("ExportIssuanceLog(%q) = %v", p, err)
		}
	}
}

func TestSave_LongNameSaves(t *testing.T) {
	h := newAppHarness(t, nil)
	writeRawLog(t, h, exportRecords)
	// 80 three-byte runes plus ".json": 245 bytes, under the usual 255-byte
	// name limit but over it once a temp prefix and suffix are added.
	name := strings.Repeat("ა", 80) + ".json"
	if err := h.app.ExportIssuanceLog(filepath.Join(t.TempDir(), name)); err != nil {
		t.Fatalf("ExportIssuanceLog: %v", err)
	}
}

func TestSaveErrorMessage(t *testing.T) {
	pathErr := func(err error) error { return &fs.PathError{Op: "open", Path: "/x", Err: err} }
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"permission", pathErr(fs.ErrPermission), msgSavePermission},
		{"missing folder", pathErr(fs.ErrNotExist), msgSaveNoFolder},
		{"other", errors.New("disk on fire"), msgSaveFailed},
		{"EROFS", pathErr(syscall.EROFS), msgSaveReadOnly},
	}
	for i, ro := range platformReadOnlyErrors {
		tests = append(tests, struct {
			name string
			err  error
			want string
		}{fmt.Sprintf("platform read-only %d", i), pathErr(ro), msgSaveReadOnly})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := saveErrorMessage(tt.err); got != tt.want {
				t.Errorf("saveErrorMessage(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

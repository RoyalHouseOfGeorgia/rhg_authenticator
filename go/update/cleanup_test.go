package update

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// populate creates directories (with a file inside, so removal must recurse)
// and empty files under root.
func populate(t *testing.T, root string, dirs, files []string) {
	t.Helper()
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(root, d, "Contents"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, d, "Contents", "f"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(root, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// listDir returns the sorted entry names of dir.
func listDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestCleanup_MissingRoot(t *testing.T) {
	res, err := cleanup(filepath.Join(t.TempDir(), "nope"), "v1.5.0")
	if err != nil {
		t.Fatalf("missing root: %v", err)
	}
	if res.Staged != nil || res.ApplyFailed != nil {
		t.Fatalf("expected empty result, got %+v", res)
	}
}

func TestCleanup_RootIsFile(t *testing.T) {
	root := filepath.Join(t.TempDir(), "update")
	if err := os.WriteFile(root, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := cleanup(root, "v1.5.0"); err == nil {
		t.Fatal("expected error when root is not a directory")
	}
}

func TestCleanup_RemovesTransients(t *testing.T) {
	root := t.TempDir()
	populate(t, root,
		[]string{"staged-1.6.0.tmp", "staged-garbage.tmp", "staged-.tmp"},
		[]string{"1.6.0.zip", "1.6.0.zip.partial", "junk.zip", "last-version.123.tmp", "last-version"},
	)
	res, err := cleanup(root, "v1.5.0")
	if err != nil {
		t.Fatal(err)
	}
	if got := listDir(t, root); !slices.Equal(got, []string{"last-version"}) {
		t.Fatalf("remaining = %v, want only last-version", got)
	}
	if res.Staged != nil || res.ApplyFailed != nil {
		t.Fatalf("expected empty result, got %+v", res)
	}
}

func TestCleanup_LeavesUnknownEntries(t *testing.T) {
	root := t.TempDir()
	populate(t, root, []string{"other-dir"}, []string{"notes.txt", "last-version"})
	if _, err := cleanup(root, "v1.5.0"); err != nil {
		t.Fatal(err)
	}
	if got := listDir(t, root); !slices.Equal(got, []string{"last-version", "notes.txt", "other-dir"}) {
		t.Fatalf("remaining = %v", got)
	}
}

func TestCleanup_StaleAndUnparsableStagedRemoved(t *testing.T) {
	root := t.TempDir()
	populate(t, root,
		[]string{"staged-1.4.0", "staged-1.5.0", "staged-v1.5", "staged-garbage", "staged-", "staged-dev"},
		[]string{"staged-1.9.0"}, // a file, not a directory: junk
	)
	res, err := cleanup(root, "v1.5.0")
	if err != nil {
		t.Fatal(err)
	}
	if got := listDir(t, root); len(got) != 0 {
		t.Fatalf("remaining = %v, want none", got)
	}
	if res.Staged != nil {
		t.Fatalf("Staged = %+v, want nil", res.Staged)
	}
}

func TestCleanup_KeepsHighestNewerStaged(t *testing.T) {
	for _, order := range [][]string{
		{"staged-1.6.0", "staged-v1.7", "staged-1.6.5"},
		{"staged-v1.7", "staged-1.6.0", "staged-1.6.5"},
	} {
		t.Run(strings.Join(order, ","), func(t *testing.T) {
			root := t.TempDir()
			populate(t, root, order, nil)
			res, err := cleanup(root, "v1.5.0")
			if err != nil {
				t.Fatal(err)
			}
			want := stagedBundle{Dir: filepath.Join(root, "staged-v1.7"), Version: "1.7.0"}
			if res.Staged == nil || *res.Staged != want {
				t.Fatalf("Staged = %+v, want %+v", res.Staged, want)
			}
			if got := listDir(t, root); !slices.Equal(got, []string{"staged-v1.7"}) {
				t.Fatalf("remaining = %v", got)
			}
			if _, err := os.Stat(filepath.Join(res.Staged.Dir, "Contents", "f")); err != nil {
				t.Fatalf("kept bundle contents missing: %v", err)
			}
		})
	}
}

func TestCleanup_DuplicateSpellingsKeepOne(t *testing.T) {
	root := t.TempDir()
	populate(t, root, []string{"staged-1.6", "staged-1.6.0"}, nil)
	res, err := cleanup(root, "1.5.0")
	if err != nil {
		t.Fatal(err)
	}
	if res.Staged == nil || res.Staged.Version != "1.6.0" {
		t.Fatalf("Staged = %+v", res.Staged)
	}
	if got := listDir(t, root); len(got) != 1 {
		t.Fatalf("remaining = %v, want exactly one", got)
	}
}

func TestCleanup_SymlinkStagedRemovedNotFollowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}
	root := t.TempDir()
	target := t.TempDir()
	populate(t, target, []string{"Victim.app"}, nil)
	if err := os.Symlink(target, filepath.Join(root, "staged-9.9.9")); err != nil {
		t.Fatal(err)
	}
	res, err := cleanup(root, "v1.5.0")
	if err != nil {
		t.Fatal(err)
	}
	if res.Staged != nil {
		t.Fatalf("symlinked staged dir must not be kept: %+v", res.Staged)
	}
	if got := listDir(t, root); len(got) != 0 {
		t.Fatalf("remaining = %v", got)
	}
	if _, err := os.Stat(filepath.Join(target, "Victim.app", "Contents", "f")); err != nil {
		t.Fatalf("symlink target must be untouched: %v", err)
	}
}

func TestCleanup_UnparsableRunningRemovesAll(t *testing.T) {
	root := t.TempDir()
	populate(t, root, []string{"staged-9.0.0"}, []string{"apply-failed-9.0.0"})
	res, err := cleanup(root, "dev")
	if err != nil {
		t.Fatal(err)
	}
	if res.Staged != nil || res.ApplyFailed != nil {
		t.Fatalf("expected empty result for dev build, got %+v", res)
	}
	if got := listDir(t, root); len(got) != 0 {
		t.Fatalf("remaining = %v", got)
	}
}

func TestCleanup_ApplyFailedMarkers(t *testing.T) {
	root := t.TempDir()
	populate(t, root, nil, []string{
		"apply-failed-1.4.0", "apply-failed-1.5.0", "apply-failed-v1.5",
		"apply-failed-garbage", "apply-failed-",
		"apply-failed-1.6.0", "apply-failed-v1.7",
	})
	res, err := cleanup(root, "v1.5.0")
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(res.ApplyFailed)
	if !slices.Equal(res.ApplyFailed, []string{"1.6.0", "1.7.0"}) {
		t.Fatalf("ApplyFailed = %v", res.ApplyFailed)
	}
	if got := listDir(t, root); !slices.Equal(got, []string{"apply-failed-1.6.0", "apply-failed-v1.7"}) {
		t.Fatalf("remaining = %v", got)
	}
}

func TestCleanup_RemovalErrorsReported(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("relies on POSIX directory permissions as non-root")
	}
	root := t.TempDir()
	populate(t, root, []string{"staged-1.0.0", "staged-2.0.0"}, nil)
	// Make one stale bundle unremovable, and leave a newer one to keep.
	locked := filepath.Join(root, "staged-1.0.0", "Contents")
	if err := os.Chmod(locked, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o700) })

	res, err := cleanup(root, "v1.5.0")
	if err == nil {
		t.Fatal("expected removal error")
	}
	if res.Staged == nil || res.Staged.Version != "2.0.0" {
		t.Fatalf("result must still be valid on partial failure: %+v", res)
	}
}

func TestMarkApplyFailed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "update")
	if isApplyFailed(root, "v1.6.0") {
		t.Fatal("no marker yet")
	}
	if err := markApplyFailed(root, "v1.6"); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"v1.6.0", "1.6.0", "v1.6", "1.6"} {
		if !isApplyFailed(root, v) {
			t.Errorf("isApplyFailed(%q) = false after marking v1.6", v)
		}
	}
	if isApplyFailed(root, "v1.6.1") {
		t.Error("other version must not be marked")
	}
	if isApplyFailed(root, "garbage") {
		t.Error("unparsable version must not be marked")
	}
	if got := listDir(t, root); !slices.Equal(got, []string{"apply-failed-1.6.0"}) {
		t.Fatalf("entries = %v", got)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(filepath.Join(root, "apply-failed-1.6.0"))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("marker mode = %v, want 0600", fi.Mode().Perm())
		}
		di, err := os.Stat(root)
		if err != nil {
			t.Fatal(err)
		}
		if di.Mode().Perm() != 0o700 {
			t.Errorf("root mode = %v, want 0700", di.Mode().Perm())
		}
	}
	// Marking again is idempotent.
	if err := markApplyFailed(root, "1.6.0"); err != nil {
		t.Fatal(err)
	}
	// Survives cleanup while newer than running.
	res, err := cleanup(root, "v1.5.0")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.ApplyFailed, []string{"1.6.0"}) {
		t.Fatalf("ApplyFailed = %v", res.ApplyFailed)
	}
}

func TestMarkApplyFailed_Errors(t *testing.T) {
	root := t.TempDir()
	for _, v := range []string{"", "dev", "../../x"} {
		if err := markApplyFailed(root, v); err == nil {
			t.Errorf("markApplyFailed(%q): expected error", v)
		}
	}
	if got := listDir(t, root); len(got) != 0 {
		t.Fatalf("no marker should be written: %v", got)
	}

	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := markApplyFailed(filepath.Join(blocker, "update"), "v1.6.0"); err == nil {
		t.Error("expected error when root cannot be created")
	}
	// Marker path occupied by a directory: WriteFile fails.
	if err := os.Mkdir(filepath.Join(root, "apply-failed-1.6.0"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := markApplyFailed(root, "v1.6.0"); err == nil {
		t.Error("expected error when marker cannot be written")
	}
}

func TestShouldShowUpdatedBanner(t *testing.T) {
	tests := []struct {
		name    string
		stored  string
		exists  bool
		running string
		want    bool
	}{
		{"missing file", "", false, "v1.5.0", false},
		{"missing file ignores stored", "v1.4.0", false, "v1.5.0", false},
		{"equal", "v1.5.0", true, "v1.5.0", false},
		{"equal mixed spelling", "1.5.0", true, "v1.5", false},
		{"older stored", "v1.4.0", true, "v1.5.0", true},
		{"older legacy stored", "v1.4", true, "v1.4.1", true},
		{"newer stored (downgrade)", "v1.6.0", true, "v1.5.0", false},
		{"unparsable stored", "garbage", true, "v1.5.0", false},
		{"empty stored", "", true, "v1.5.0", false},
		{"unparsable running", "v1.4.0", true, "dev", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldShowUpdatedBanner(tt.stored, tt.exists, tt.running); got != tt.want {
				t.Errorf("shouldShowUpdatedBanner(%q, %v, %q) = %v, want %v",
					tt.stored, tt.exists, tt.running, got, tt.want)
			}
		})
	}
}

func TestLastVersion_RoundTrip(t *testing.T) {
	dataDir := t.TempDir()
	if v, ok := readLastVersion(dataDir); ok || v != "" {
		t.Fatalf("readLastVersion on fresh dir = (%q, %v), want (\"\", false)", v, ok)
	}
	if err := writeLastVersion(dataDir, "v1.5.0"); err != nil {
		t.Fatal(err)
	}
	v, ok := readLastVersion(dataDir)
	if !ok || v != "v1.5.0" {
		t.Fatalf("readLastVersion = (%q, %v), want (\"v1.5.0\", true)", v, ok)
	}
	// Overwrite.
	if err := writeLastVersion(dataDir, "v1.6.0"); err != nil {
		t.Fatal(err)
	}
	if v, _ := readLastVersion(dataDir); v != "v1.6.0" {
		t.Fatalf("after overwrite = %q", v)
	}
	path := filepath.Join(dataDir, "update", "last-version")
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("last-version mode = %v, want 0600", fi.Mode().Perm())
		}
		di, err := os.Stat(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		if di.Mode().Perm() != 0o700 {
			t.Errorf("update dir mode = %v, want 0700", di.Mode().Perm())
		}
	}
	// No temp files left behind, and cleanup preserves last-version.
	if _, err := cleanup(stagingRoot(dataDir), "v1.6.0"); err != nil {
		t.Fatal(err)
	}
	if got := listDir(t, stagingRoot(dataDir)); !slices.Equal(got, []string{"last-version"}) {
		t.Fatalf("entries = %v", got)
	}
}

func TestReadLastVersion_TrimsAndBounds(t *testing.T) {
	dataDir := t.TempDir()
	root := stagingRoot(dataDir)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "last-version")
	if err := os.WriteFile(path, []byte("  v1.5.0\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if v, ok := readLastVersion(dataDir); !ok || v != "v1.5.0" {
		t.Fatalf("got (%q, %v)", v, ok)
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("9", 10_000)), 0o600); err != nil {
		t.Fatal(err)
	}
	if v, ok := readLastVersion(dataDir); !ok || len(v) != maxLastVersionBytes {
		t.Fatalf("oversized read: len=%d ok=%v", len(v), ok)
	}
	// Unreadable (a directory): treated as missing.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if v, ok := readLastVersion(dataDir); ok || v != "" {
		t.Fatalf("directory at path: got (%q, %v)", v, ok)
	}
}

func TestWriteLastVersion_Errors(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeLastVersion(blocker, "v1.5.0"); err == nil {
		t.Error("expected error when update dir cannot be created")
	}

	// Rename onto a non-empty directory fails; temp file must be cleaned up.
	dataDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(stagingRoot(dataDir), "last-version", "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeLastVersion(dataDir, "v1.5.0"); err == nil {
		t.Error("expected error when rename fails")
	}
	if got := listDir(t, stagingRoot(dataDir)); !slices.Equal(got, []string{"last-version"}) {
		t.Fatalf("temp file left behind: %v", got)
	}

	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		ro := t.TempDir()
		if err := os.MkdirAll(stagingRoot(ro), 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(stagingRoot(ro), 0o700) })
		if err := writeLastVersion(ro, "v1.5.0"); err == nil {
			t.Error("expected error when temp file cannot be created")
		}
	}
}

func TestStagingRoot(t *testing.T) {
	if got, want := stagingRoot("/data"), filepath.Join("/data", "update"); got != want {
		t.Fatalf("stagingRoot = %q, want %q", got, want)
	}
}

func TestCleanup_DropsStagedWithApplyFailedMarker(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "staged-1.5.0"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := markApplyFailed(root, "1.5.0"); err != nil {
		t.Fatal(err)
	}
	res, err := cleanup(root, "v1.4.0")
	if err != nil {
		t.Fatal(err)
	}
	if res.Staged != nil {
		t.Fatalf("staged bundle with apply-failed marker offered: %+v", res.Staged)
	}
	if !slices.Equal(res.ApplyFailed, []string{"1.5.0"}) {
		t.Fatalf("ApplyFailed = %v", res.ApplyFailed)
	}
	assertAbsent(t, filepath.Join(root, "staged-1.5.0"))
}

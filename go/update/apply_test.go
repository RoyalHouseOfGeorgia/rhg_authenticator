package update

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fakeApply is an in-memory applyDeps backend.
type fakeApply struct {
	versions   map[string]string // bundle path → plist version
	versionErr map[string]error
	verifyErr  error
	swapErr    error
	swaps      [][2]string
	verifies   []verifyCall
}

func (f *fakeApply) deps() applyDeps {
	return applyDeps{
		bundleVersion: func(b string) (string, error) {
			if err := f.versionErr[b]; err != nil {
				return "", err
			}
			return f.versions[b], nil
		},
		verify: func(b, v string) error {
			f.verifies = append(f.verifies, verifyCall{b, v})
			return f.verifyErr
		},
		swap: func(staged, current string) error {
			f.swaps = append(f.swaps, [2]string{staged, current})
			return f.swapErr
		},
	}
}

const curBundle = "/Applications/RHG Authenticator.app"

// newTestStaged creates root/staged-1.5.0/RHG Authenticator.app on disk (apply
// checks that the staged bundle still exists) and returns it.
func newTestStaged(t *testing.T, root string) stagedBundle {
	t.Helper()
	dir := filepath.Join(root, "staged-1.5.0")
	app := filepath.Join(dir, testAppName)
	if err := os.MkdirAll(app, 0o700); err != nil {
		t.Fatal(err)
	}
	return stagedBundle{Dir: dir, App: app, Version: "1.5.0"}
}

func TestApply(t *testing.T) {
	boom := errors.New("boom")
	cases := []struct {
		name       string
		cur        string
		staged     string
		running    string
		curErr     error
		stagedErr  error
		verifyErr  error
		swapErr    error
		vanish     bool
		wantErr    bool
		wantSwap   bool
		wantVerify bool
		wantMarker bool
		wantGuard  bool
	}{
		{name: "success", cur: "1.4.0", staged: "1.5.0", running: "v1.4.0", wantSwap: true, wantVerify: true},
		{name: "success legacy running", cur: "1.4", staged: "1.5.0", running: "v1.4", wantSwap: true, wantVerify: true},
		{name: "current not running (already swapped)", cur: "1.5.0", staged: "1.4.0", running: "v1.4.0", wantErr: true, wantGuard: true},
		{name: "current unreadable", curErr: boom, staged: "1.5.0", running: "v1.4.0", wantErr: true, wantGuard: true},
		{name: "running unparsable", cur: "1.4.0", staged: "1.5.0", running: "dev", wantErr: true, wantGuard: true},
		{name: "staged plist != dir version (old bundle in staged dir)", cur: "1.4.0", staged: "1.3.0", running: "v1.4.0", wantErr: true, wantGuard: true},
		{name: "staged equals running", cur: "1.5.0", staged: "1.5.0", running: "v1.5.0", wantErr: true, wantGuard: true},
		{name: "staged older than running", cur: "1.6.0", staged: "1.5.0", running: "v1.6.0", wantErr: true, wantGuard: true},
		{name: "staged unreadable", cur: "1.4.0", stagedErr: boom, running: "v1.4.0", wantErr: true, wantMarker: true},
		{name: "verify fails", cur: "1.4.0", staged: "1.5.0", running: "v1.4.0", verifyErr: boom, wantErr: true, wantVerify: true, wantMarker: true},
		{name: "swap fails", cur: "1.4.0", staged: "1.5.0", running: "v1.4.0", swapErr: boom, wantErr: true, wantSwap: true, wantVerify: true, wantMarker: true},
		{name: "staged bundle vanished", cur: "1.4.0", staged: "1.5.0", running: "v1.4.0", vanish: true, wantErr: true, wantGuard: true},
		{name: "verify transient (no marker)", cur: "1.4.0", staged: "1.5.0", running: "v1.4.0", verifyErr: fmt.Errorf("codesign: %w", errTransient), wantErr: true, wantVerify: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			sb := newTestStaged(t, root)
			stagedApp := sb.App
			if tc.vanish {
				if err := os.RemoveAll(sb.Dir); err != nil {
					t.Fatal(err)
				}
			}
			f := &fakeApply{
				versions:   map[string]string{curBundle: tc.cur, stagedApp: tc.staged},
				versionErr: map[string]error{curBundle: tc.curErr, stagedApp: tc.stagedErr},
				verifyErr:  tc.verifyErr,
				swapErr:    tc.swapErr,
			}
			err := apply(root, sb, curBundle, tc.running, f.deps())

			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if errors.Is(err, errApplyGuard) != tc.wantGuard {
				t.Fatalf("errApplyGuard = %v, want %v (err %v)", errors.Is(err, errApplyGuard), tc.wantGuard, err)
			}
			if tc.wantSwap {
				if len(f.swaps) != 1 || f.swaps[0] != [2]string{stagedApp, curBundle} {
					t.Fatalf("swaps = %q, want one staged→current", f.swaps)
				}
			} else if len(f.swaps) != 0 {
				t.Fatalf("swap called: %q", f.swaps)
			}
			if tc.wantVerify {
				if len(f.verifies) != 1 || f.verifies[0] != (verifyCall{stagedApp, "1.5.0"}) {
					t.Fatalf("verifies = %+v", f.verifies)
				}
			} else if len(f.verifies) != 0 {
				t.Fatalf("verify called: %+v", f.verifies)
			}
			if got := isApplyFailed(root, "1.5.0"); got != tc.wantMarker {
				t.Fatalf("apply-failed marker = %v, want %v", got, tc.wantMarker)
			}
			if errors.Is(tc.verifyErr, errTransient) && !errors.Is(err, errTransient) {
				t.Fatalf("err %v lost errTransient", err)
			}
			if tc.wantMarker && !errors.Is(err, boom) {
				t.Fatalf("err %v does not wrap cause", err)
			}
		})
	}
}

func TestApply_MarkerWriteFails(t *testing.T) {
	// root is a file, so the marker cannot be written; both errors surface.
	root := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(root, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	swapErr := errors.New("EPERM")
	sb := newTestStaged(t, t.TempDir())
	f := &fakeApply{
		versions: map[string]string{curBundle: "1.4.0", sb.App: "1.5.0"},
		swapErr:  swapErr,
	}
	err := apply(root, sb, curBundle, "v1.4.0", f.deps())
	if !errors.Is(err, swapErr) {
		t.Fatalf("err = %v, want swap error", err)
	}
	if !strings.Contains(err.Error(), "create staging root") {
		t.Fatalf("marker error not joined: %v", err)
	}
}

// makeStaged creates <tmp>/staged-<ver>/ containing the given entries
// (names ending in "/" are directories, others empty files).
func makeStaged(t *testing.T, ver string, entries ...string) stagedBundle {
	t.Helper()
	dir := filepath.Join(t.TempDir(), stagedPrefix+ver)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		p := filepath.Join(dir, e)
		var err error
		if e[len(e)-1] == '/' {
			err = os.MkdirAll(p, 0o700)
		} else {
			err = os.WriteFile(p, nil, 0o600)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	return stagedBundle{Dir: dir, Version: ver}
}

func TestReadyStaged(t *testing.T) {
	boom := errors.New("boom")
	cases := []struct {
		name      string
		entries   []string
		version   string
		verErr    error
		verifyErr error
		wantErr   string // "" = success
	}{
		{name: "ok", entries: []string{testAppName + "/"}, version: "1.5.0"},
		{name: "version mismatch", entries: []string{testAppName + "/"}, version: "1.4.0", wantErr: `bundle is "1.4.0"`},
		{name: "version unreadable", entries: []string{testAppName + "/"}, verErr: boom, wantErr: "boom"},
		{name: "verify fails", entries: []string{testAppName + "/"}, version: "1.5.0", verifyErr: boom, wantErr: "boom"},
		{name: "empty dir", entries: nil, version: "1.5.0", wantErr: "exactly one .app"},
		{name: "no .app inside", entries: []string{"Other/"}, version: "1.5.0", wantErr: "exactly one .app"},
		{name: "hidden .app", entries: []string{"._X.app/"}, version: "1.5.0", wantErr: "exactly one .app"},
		{name: ".app is a file", entries: []string{testAppName}, version: "1.5.0", wantErr: "exactly one .app"},
		{name: "extra entry", entries: []string{testAppName + "/", "stray"}, version: "1.5.0", wantErr: "exactly one .app"},
		{name: "two bundles", entries: []string{"A.app/", "B.app/"}, version: "1.5.0", wantErr: "exactly one .app"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sb := makeStaged(t, "1.5.0", tc.entries...)
			want := filepath.Join(sb.Dir, testAppName)
			f := &fakeApply{
				versions:   map[string]string{want: tc.version},
				versionErr: map[string]error{want: tc.verErr},
				verifyErr:  tc.verifyErr,
			}
			got, err := readyStaged(sb, f.deps())
			// readyStaged never deletes; the caller does.
			assertExists(t, sb.Dir)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				if got != (stagedBundle{}) {
					t.Fatalf("got %+v on failure", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != (stagedBundle{Dir: sb.Dir, App: want, Version: "1.5.0"}) {
				t.Fatalf("got %+v", got)
			}
			if !slices.Equal(f.verifies, []verifyCall{{want, "1.5.0"}}) {
				t.Fatalf("verifies = %+v", f.verifies)
			}
		})
	}
}

func TestReadyStaged_Missing(t *testing.T) {
	missing := stagedBundle{Dir: filepath.Join(t.TempDir(), "staged-1.5.0"), Version: "1.5.0"}
	if _, err := readyStaged(missing, (&fakeApply{}).deps()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want not-exist", err)
	}
}

func TestRelaunchCommand(t *testing.T) {
	name, args := relaunchCommand(curBundle)
	if name != "/usr/bin/open" || !slices.Equal(args, []string{"-n", curBundle}) {
		t.Fatalf("relaunch = %q %q", name, args)
	}
}

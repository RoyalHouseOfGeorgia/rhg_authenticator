package update

import (
	"errors"
	"slices"
	"testing"
)

func TestBundleFromExecutable(t *testing.T) {
	cases := []struct {
		exe    string
		want   string
		wantOK bool
	}{
		{"/Applications/RHG Authenticator.app/Contents/MacOS/rhg-authenticator", "/Applications/RHG Authenticator.app", true},
		{"/Users/k/Applications/X.app/Contents/MacOS/bin", "/Users/k/Applications/X.app", true},
		{"/Applications/X.app/Contents/MacOS/../MacOS/bin", "/Applications/X.app", true},
		{"/usr/local/bin/rhg-authenticator", "", false},
		{"/Applications/X.app/Contents/Resources/bin", "", false},
		{"/Applications/X.app/Other/MacOS/bin", "", false},
		{"/Applications/X/Contents/MacOS/bin", "", false},
		{"/Applications/.app/Contents/MacOS/bin", "", false},
		{"/Applications/._X.app/Contents/MacOS/bin", "", false},
		{"/Contents/MacOS/bin", "", false},
		{"X.app/Contents/MacOS/bin", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := bundleFromExecutable(tc.exe)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("bundleFromExecutable(%q) = %q, %v; want %q, %v", tc.exe, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestEligible(t *testing.T) {
	const home = "/Users/k"
	denied := errors.New("permission denied")
	cases := []struct {
		name       string
		bundle     string
		home       string
		readOnly   []string
		wantOK     bool
		wantReason string
	}{
		{"system Applications", "/Applications/RHG Authenticator.app", home, nil, true, ""},
		{"user Applications", "/Users/k/Applications/RHG Authenticator.app", home, nil, true, ""},
		{"user Applications trailing slash home", "/Users/k/Applications/X.app", "/Users/k/", nil, true, ""},
		{"uncleaned bundle path", "/Applications/./X.app/", home, nil, true, ""},
		{"translocated", "/private/var/folders/ab/T/AppTranslocation/1234-ABCD/d/X.app", home, nil, false, reasonTranslocate},
		{"translocated under Applications", "/Applications/AppTranslocation/X.app", home, nil, false, reasonTranslocate},
		{"Downloads", "/Users/k/Downloads/X.app", home, nil, false, reasonOutside},
		{"Applications subfolder", "/Applications/Utilities/X.app", home, nil, false, reasonOutside},
		{"other user's Applications", "/Users/other/Applications/X.app", home, nil, false, reasonOutside},
		{"dot-dot escape", "/Applications/../tmp/X.app", home, nil, false, reasonOutside},
		{"lookalike prefix", "/ApplicationsEvil/X.app", home, nil, false, reasonOutside},
		{"empty home still allows /Applications", "/Applications/X.app", "", nil, true, ""},
		{"relative bundle", "Applications/X.app", "", nil, false, reasonOutside},
		{"relative home not matched", "/cwd/Applications/X.app", ".", nil, false, reasonOutside},
		{"read-only parent", "/Applications/X.app", home, []string{"/Applications"}, false, reasonNotWritable},
		{"read-only bundle", "/Applications/X.app", home, []string{"/Applications/X.app"}, false, reasonNotWritable},
		{"read-only user parent", "/Users/k/Applications/X.app", home, []string{"/Users/k/Applications"}, false, reasonNotWritable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var checked []string
			access := func(p string) error {
				checked = append(checked, p)
				if slices.Contains(tc.readOnly, p) {
					return denied
				}
				return nil
			}
			ok, reason := eligible(tc.bundle, tc.home, access)
			if ok != tc.wantOK || reason != tc.wantReason {
				t.Fatalf("eligible = %v, %q; want %v, %q", ok, reason, tc.wantOK, tc.wantReason)
			}
			if tc.wantOK && len(checked) != 2 {
				t.Fatalf("access checked %q, want parent and bundle", checked)
			}
		})
	}
}

func TestEligibleFromExe(t *testing.T) {
	writable := func(string) error { return nil }
	cases := []struct {
		exe        string
		wantBundle string
		wantReason string
	}{
		{"/Applications/RHG Authenticator.app/Contents/MacOS/rhg-authenticator", "/Applications/RHG Authenticator.app", ""},
		{"/Users/x/Downloads/RHG Authenticator.app/Contents/MacOS/rhg-authenticator", "/Users/x/Downloads/RHG Authenticator.app", reasonOutside},
		{"/usr/local/bin/rhg-authenticator", "", reasonNotBundle},
	}
	for _, tc := range cases {
		bundle, ok, reason := eligibleFromExe(tc.exe, "/Users/x", writable)
		if bundle != tc.wantBundle || reason != tc.wantReason || ok != (tc.wantReason == "") {
			t.Errorf("eligibleFromExe(%q) = %q, %v, %q; want %q, %q", tc.exe, bundle, ok, reason, tc.wantBundle, tc.wantReason)
		}
	}
}

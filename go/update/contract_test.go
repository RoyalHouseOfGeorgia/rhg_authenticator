package update

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// These tests tie hand-written constants to the committed files they must
// agree with; a mismatch would make every update fail closed or fall back to
// the manual Download banner, with no error anywhere else.

func TestPinnedRequirement_MatchesInfoPlistIdentifier(t *testing.T) {
	plist, err := os.ReadFile("../packaging/macos/Info.plist")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`<key>CFBundleIdentifier</key>\s*<string>([^<]+)</string>`).FindSubmatch(plist)
	if m == nil {
		t.Fatal("CFBundleIdentifier not found in Info.plist")
	}
	if want := `identifier "` + string(m[1]) + `" and `; !strings.HasPrefix(PinnedRequirement, want) {
		t.Fatalf("PinnedRequirement %q does not start with %q", PinnedRequirement, want)
	}
}

func TestDarwinAssetName_PublishedByWorkflow(t *testing.T) {
	wf, err := os.ReadFile("../../.github/workflows/build.yml")
	if err != nil {
		t.Fatal(err)
	}
	// sign-macos uploads exactly this file (the dry-run job never uploads).
	if !strings.Contains(string(wf), "path: out/"+darwinAssetName) {
		t.Fatalf("build.yml does not publish %s from sign-macos", darwinAssetName)
	}
}

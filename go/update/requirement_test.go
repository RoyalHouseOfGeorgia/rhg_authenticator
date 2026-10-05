package update

import (
	"regexp"
	"strings"
	"testing"
)

func TestPinnedRequirement_Format(t *testing.T) {
	re := regexp.MustCompile(`^identifier "ge\.royalhouseofgeorgia\.rhg-authenticator" and certificate leaf = H"[0-9a-f]{40}"$`)
	if !re.MatchString(PinnedRequirement) {
		t.Fatalf("PinnedRequirement has unexpected format: %s", PinnedRequirement)
	}
	// The all-zero placeholder matches no certificate: shipping it would make
	// every update fail closed.
	if strings.Contains(PinnedRequirement, `H"`+strings.Repeat("0", 40)+`"`) {
		t.Fatal("PinnedRequirement is still the placeholder; paste requirement.txt from scripts/gen-macos-cert.sh")
	}
}

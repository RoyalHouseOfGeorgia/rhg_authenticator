package update

import (
	"regexp"
	"testing"
)

func TestPinnedRequirement_Format(t *testing.T) {
	re := regexp.MustCompile(`^identifier "ge\.royalhouseofgeorgia\.rhg-authenticator" and certificate leaf = H"[0-9a-f]{40}"$`)
	if !re.MatchString(PinnedRequirement) {
		t.Fatalf("PinnedRequirement has unexpected format: %s", PinnedRequirement)
	}
}

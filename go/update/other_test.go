//go:build !darwin

package update

import (
	"errors"
	"testing"
)

func TestUnsupportedStubs(t *testing.T) {
	if err := verifyBundle("b", PinnedRequirement, "1.5.0"); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("verifyBundle = %v", err)
	}
	if v, err := bundleVersion("b"); v != "" || !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("bundleVersion = %q, %v", v, err)
	}
	if err := swapBundles("a", "b"); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("swapBundles = %v", err)
	}
	if err := relaunch("b"); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("relaunch = %v", err)
	}
	if b, ok, reason := currentBundleEligible(); b != "" || ok || reason != reasonUnsupported {
		t.Errorf("currentBundleEligible = %q, %v, %q", b, ok, reason)
	}
}

package gui

import (
	"strings"
	"testing"
	"time"
)

// --- revocationTimeout constant tests ---

func TestRevocationTimeout_Value(t *testing.T) {
	if revocationTimeout != 180*time.Second {
		t.Errorf("revocationTimeout = %v, want 180s", revocationTimeout)
	}
}

func TestRevocationTimeout_GreaterThanZero(t *testing.T) {
	if revocationTimeout <= 0 {
		t.Errorf("revocationTimeout should be positive, got %v", revocationTimeout)
	}
}

// --- revocationCacheUnavailableMsg constant tests ---

func TestRevocationCacheUnavailableMsg_NotEmpty(t *testing.T) {
	if revocationCacheUnavailableMsg == "" {
		t.Error("revocationCacheUnavailableMsg should not be empty")
	}
}

func TestRevocationCacheUnavailableMsg_Value(t *testing.T) {
	want := "Revocation data not loaded. Try refreshing."
	if revocationCacheUnavailableMsg != want {
		t.Errorf("revocationCacheUnavailableMsg = %q, want %q", revocationCacheUnavailableMsg, want)
	}
}

func TestRevocationCacheUnavailableMsg_ContainsRefreshHint(t *testing.T) {
	if !strings.Contains(revocationCacheUnavailableMsg, "refreshing") {
		t.Error("message should mention refreshing as a remedy")
	}
}

func TestRevocationCacheUnavailableMsg_ContainsNotLoaded(t *testing.T) {
	if !strings.Contains(revocationCacheUnavailableMsg, "not loaded") {
		t.Error("message should indicate data is not loaded")
	}
}

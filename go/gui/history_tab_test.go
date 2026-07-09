package gui

import (
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/log"
)

// Note on test coverage for this file: the login-dependent widget glue in
// NewHistoryTab (signInButton Show/Hide, Revoke re-gating) is deliberately NOT
// driver-tested here. NewHistoryTab kicks off fetchRevocations at construction
// (a real network fetch + goroutine), and under the Fyne test driver its
// fyne.Do body runs inline on that goroutine, racing any synchronous
// refreshLoginState() call (trips -race). The compensating coverage is: this
// pure shouldEnableRevoke table test (the decision logic), the regmgr
// updateLoginUI observer tests (the push wiring), and a manual /verify pass on a
// target platform (the pixels). Do not "add the missing construction test" — it
// reintroduces the race.

// TestShouldEnableRevoke pins the Revoke-enable rule: enabled only when a usable
// client exists AND the revocation cache is ready AND a record is selected AND
// that record is not revoked. Covers the nil-safe form (selected == nil, the
// login-refresh case), the not-ready cache (failed/pending fetch), the nil
// revoked map (startup), and case-insensitive revocation lookup both directions
// (production stores keys lowercase).
func TestShouldEnableRevoke(t *testing.T) {
	rec := &log.IssuanceRecord{PayloadSHA256: "abc123"}
	recMixed := &log.IssuanceRecord{PayloadSHA256: "ABC123"} // same hash, mixed case

	tests := []struct {
		name       string
		clientNil  bool
		cacheReady bool
		selected   *log.IssuanceRecord
		revoked    map[string]bool
		want       bool
	}{
		{"no usable client", true, true, rec, map[string]bool{}, false},
		{"cache not ready (failed/pending fetch)", false, false, rec, map[string]bool{}, false},
		{"nil selection (no panic)", false, true, nil, map[string]bool{}, false},
		{"nil revoked map (startup)", false, true, rec, nil, true},
		{"selected and revoked", false, true, rec, map[string]bool{"abc123": true}, false},
		{"selected not revoked", false, true, rec, map[string]bool{}, true},
		{"mixed-case hash present in revoked", false, true, recMixed, map[string]bool{"abc123": true}, false},
		{"mixed-case hash absent from revoked", false, true, recMixed, map[string]bool{"other": true}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldEnableRevoke(tt.clientNil, tt.cacheReady, tt.selected, tt.revoked); got != tt.want {
				t.Errorf("shouldEnableRevoke(%v, %v, %+v, %v) = %v, want %v",
					tt.clientNil, tt.cacheReady, tt.selected, tt.revoked, got, tt.want)
			}
		})
	}
}

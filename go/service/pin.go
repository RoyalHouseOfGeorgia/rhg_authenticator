package service

import (
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/royalhouseofgeorgia/rhg-authenticator/yubikey"
)

// ErrSigningCancelled is returned when the user dismisses the PIN dialog.
// This is a normal outcome, not an error — the sign flow should show a
// neutral status message rather than an error.
var ErrSigningCancelled = errors.New("signing cancelled")

// ErrPINEntryTimedOut is returned when the PIN dialog is left unanswered past
// the timeout. Like ErrSigningCancelled it is a neutral outcome. It is a typed
// sentinel (matched via errors.Is) rather than a free-text error because the
// literal string "PIN entry timed out" matches core.ClassifyHardwareError's
// \bpin\b regex and would otherwise be misclassified as a hardware PIN error.
var ErrPINEntryTimedOut = errors.New("PIN entry timed out")

// ErrPINCacheUnavailable is returned when the PIN cannot be secured in mlock'd
// memory. Same misclassification hazard as ErrPINEntryTimedOut — matched via
// errors.Is, so it MUST be returned bare or %w-wrapped (never %v-joined).
var ErrPINCacheUnavailable = errors.New("cannot secure PIN in memory")

// DefaultPINEntryTimeout is the deadline for PIN dialog entry. Balances a
// multi-sign session against an unattended workstation.
const DefaultPINEntryTimeout = 5 * time.Minute

// PIVMaxPINBytes is the PIV VERIFY command's PIN byte limit (piv-go encodePIN).
const PIVMaxPINBytes = 8

// TruncatePINToBytes returns the longest prefix of s whose UTF-8 encoding is
// <= maxBytes, cut on a rune boundary so the result is always valid UTF-8.
func TruncatePINToBytes(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	for maxBytes > 0 && !utf8.RuneStart(s[maxBytes]) {
		maxBytes--
	}
	return s[:maxBytes]
}

// ProcessPINResult applies cancel/cap/cache semantics to a PIN submitted from the
// dialog. An empty submission means the user cancelled. The PIN is capped to the PIV
// byte limit BEFORE it is cached, so the cache only ever stores a valid-length value
// and later cache hits return an already-capped PIN. A cache-set failure is surfaced
// (not swallowed) so the user restarts instead of signing with an unprotected PIN.
//
// The PIN is cached here, before the card validates it. Only a later piv.AuthErr
// clears it (via ClearPINCacheOnAuthError); a non-auth failure (no key, cert read,
// or a transient PC/SC reset) leaves the entered PIN cached until the timeout.
// Accepted tradeoff: if that PIN was mistyped it is replayed once on the next
// sign, costing a single PIV retry before the resulting AuthErr clears it —
// bounded, self-healing, and not attacker-drivable on a single-operator desktop.
// Clearing on every non-auth failure was rejected: it would force PIN re-entry
// after a transient reset, defeating this flow's retry-without-re-prompt goal.
func ProcessPINResult(pin string, cache *yubikey.PinCache) (string, error) {
	if pin == "" {
		return "", ErrSigningCancelled
	}
	pin = TruncatePINToBytes(pin, PIVMaxPINBytes)
	if cache.Enabled() {
		if err := cache.Set(pin); err != nil {
			// %w so SignFlowErrorMessage can match ErrPINCacheUnavailable via
			// errors.Is (a %v join would fall into the \bpin\b misclassification).
			return "", fmt.Errorf("%w: %v", ErrPINCacheUnavailable, err)
		}
	}
	return pin, nil
}

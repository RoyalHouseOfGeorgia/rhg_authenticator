package service

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

func TestBuildEntry(t *testing.T) {
	multiline := "Multi\nline\nnote with special chars: é"
	cases := []struct {
		name                 string
		authority, key, note string
		want                 core.KeyEntry
	}{
		{
			name: "basic", authority: "Test Authority", key: "dGVzdGtleQ==", note: "a note",
			want: core.KeyEntry{Authority: "Test Authority", From: "2026-01-01", Algorithm: "Ed25519", PublicKey: "dGVzdGtleQ==", Note: "a note"},
		},
		{
			name: "trims and NFC-normalizes authority", authority: "  caf\u0065\u0301  ", key: "key",
			want: core.KeyEntry{Authority: "caf\u00e9", From: "2026-01-01", Algorithm: "Ed25519", PublicKey: "key"},
		},
		{
			name: "preserves note", authority: "Auth", key: "key", note: multiline,
			want: core.KeyEntry{Authority: "Auth", From: "2026-01-01", Algorithm: "Ed25519", PublicKey: "key", Note: multiline},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := buildEntry(tc.authority, "2026-01-01", nil, tc.key, tc.note); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("buildEntry = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestBuildEntry_WithExpiry(t *testing.T) {
	to := "2027-12-31"
	entry := buildEntry("Auth", "2026-01-01", &to, "key123", "")
	if entry.To == nil {
		t.Fatal("To should not be nil when expiry is set")
	}
	if *entry.To != "2027-12-31" {
		t.Errorf("To = %q, want %q", *entry.To, "2027-12-31")
	}
}

func TestValidateEntryForm(t *testing.T) {
	cases := []struct {
		name                 string
		authority, from, key string
		noExpiry             bool
		to                   string
		wantErr              bool
		wantContains         string
	}{
		{name: "valid", authority: "Auth", from: "2026-01-01", key: "key", noExpiry: true},
		{name: "empty authority", authority: "", from: "2026-01-01", key: "key", noExpiry: true, wantErr: true},
		{name: "whitespace authority", authority: "   ", from: "2026-01-01", key: "key", noExpiry: true, wantErr: true},
		{name: "empty from", authority: "Auth", from: "", key: "key", noExpiry: true, wantErr: true},
		{name: "invalid from date", authority: "Auth", from: "not-a-date", key: "key", noExpiry: true, wantErr: true},
		{name: "invalid to date", authority: "Auth", from: "2026-01-01", key: "key", to: "not-a-date", wantErr: true},
		{name: "no expiry skips to validation", authority: "Auth", from: "2026-01-01", key: "key", noExpiry: true, to: "garbage"},
		{name: "to required when no expiry unchecked", authority: "Auth", from: "2026-01-01", key: "key", wantErr: true, wantContains: "To date is required"},
		// Revoking a key registered with a future From sets To to today.
		{name: "to before from accepted", authority: "Auth", from: "2026-06-01", key: "key", to: "2025-01-01"},
		{name: "to equals from", authority: "Auth", from: "2026-01-01", key: "key", to: "2026-01-01"},
		{name: "empty key", authority: "Auth", from: "2026-01-01", key: "", noExpiry: true, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateEntryForm(tc.authority, tc.from, tc.key, tc.noExpiry, tc.to)
			if !tc.wantErr {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantContains) {
				t.Errorf("error = %v, want containing %q", err, tc.wantContains)
			}
		})
	}
}

func TestImportKeyErrorMessage(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "reset error (wrapped verify pin chain)",
			err:  errors.New("sign: signing failed: verify pin: transmitting request: the smart card has been reset, so any shared state information is invalid"),
			want: core.MsgYubiKeyReset,
		},
		{
			name: "pcsc error",
			err:  errors.New("pcsc daemon not running"),
			want: "Smart card service not available.",
		},
		{
			name: "generic error",
			err:  errors.New("something else"),
			want: "No YubiKey detected — plug in and try again.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := importKeyErrorMessage(tt.err); got != tt.want {
				t.Errorf("importKeyErrorMessage(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

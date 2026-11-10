package service

import (
	"testing"
	"unicode/utf8"

	"github.com/royalhouseofgeorgia/rhg-authenticator/yubikey"
)

// TestTruncatePINToBytes verifies the PIN is capped to 8 bytes on a rune
// boundary, always yielding valid UTF-8.
func TestTruncatePINToBytes(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"under limit", "1234", "1234"},
		{"exactly 8 bytes", "12345678", "12345678"},
		{"over by one ascii", "123456789", "12345678"},
		{"multibyte cut on boundary", "café1234", "café123"},
		{"multibyte must not split rune", "1234567é", "1234567"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TruncatePINToBytes(tt.in, PIVMaxPINBytes)
			if got != tt.want {
				t.Errorf("TruncatePINToBytes(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if len(got) > PIVMaxPINBytes {
				t.Errorf("result %q is %d bytes, want <= %d", got, len(got), PIVMaxPINBytes)
			}
			if !utf8.ValidString(got) {
				t.Errorf("result %q is not valid UTF-8", got)
			}
		})
	}
}

// TestProcessPINResult verifies the cap/cache semantics of the pure helper
// used by App.readPIN after the prompt returns.
func TestProcessPINResult(t *testing.T) {
	t.Run("enabled caps ascii before caching", func(t *testing.T) {
		cache := yubikey.NewPinCache()
		cache.SetEnabled(true)

		pin, err := processPINResult("123456789", cache)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pin != "12345678" {
			t.Errorf("pin = %q, want %q", pin, "12345678")
		}
		cached, ok := cache.Get()
		if !ok || cached != "12345678" {
			t.Errorf("cache.Get() = (%q, %v), want (%q, true)", cached, ok, "12345678")
		}
	})

	t.Run("enabled caps multibyte on rune boundary before caching", func(t *testing.T) {
		cache := yubikey.NewPinCache()
		cache.SetEnabled(true)

		pin, err := processPINResult("café1234", cache)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pin != "café123" {
			t.Errorf("pin = %q, want %q", pin, "café123")
		}
		cached, ok := cache.Get()
		if !ok || cached != "café123" {
			t.Errorf("cache.Get() = (%q, %v), want (%q, true)", cached, ok, "café123")
		}
	})

	t.Run("disabled caps but does not cache", func(t *testing.T) {
		cache := yubikey.NewPinCache()
		cache.SetEnabled(false)

		pin, err := processPINResult("123456789", cache)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pin != "12345678" {
			t.Errorf("pin = %q, want %q", pin, "12345678")
		}
		if cached, ok := cache.Get(); ok {
			t.Errorf("cache.Get() = (%q, %v), want (\"\", false)", cached, ok)
		}
	})

	t.Run("enabled short pin cached verbatim", func(t *testing.T) {
		cache := yubikey.NewPinCache()
		cache.SetEnabled(true)

		pin, err := processPINResult("123456", cache)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pin != "123456" {
			t.Errorf("pin = %q, want %q", pin, "123456")
		}
		cached, ok := cache.Get()
		if !ok || cached != "123456" {
			t.Errorf("cache.Get() = (%q, %v), want (%q, true)", cached, ok, "123456")
		}
	})
}

package gui

import (
	"testing"
	"unicode/utf8"

	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/yubikey"
)

// TestMakePinReader_CacheHit verifies that when the PinCache has a valid entry,
// the readPin closure returns the cached PIN immediately without showing a dialog.
func TestMakePinReader_CacheHit(t *testing.T) {
	cache := yubikey.NewPinCache()
	cache.SetEnabled(true)
	if err := cache.Set("123456"); err != nil {
		t.Fatalf("cache.Set failed: %v", err)
	}

	// window is nil — the closure must not touch Fyne for a cache hit.
	readPin := MakePinReader(nil, cache)

	pin, err := readPin()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pin != "123456" {
		t.Errorf("pin = %q, want %q", pin, "123456")
	}
}

// TestMakePinReader_CacheHit_ReturnsExactValue verifies the cached PIN is
// returned verbatim (no trimming, encoding, etc.).
func TestMakePinReader_CacheHit_ReturnsExactValue(t *testing.T) {
	cache := yubikey.NewPinCache()
	cache.SetEnabled(true)
	if err := cache.Set("  spaces  "); err != nil {
		t.Fatalf("cache.Set failed: %v", err)
	}

	readPin := MakePinReader(nil, cache)

	pin, err := readPin()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pin != "  spaces  " {
		t.Errorf("pin = %q, want %q", pin, "  spaces  ")
	}
}

// TestMakePinReader_CacheDisabled_NoHit verifies that when caching is disabled,
// the cache is not consulted (Get returns false).
func TestMakePinReader_CacheDisabled_NoHit(t *testing.T) {
	cache := yubikey.NewPinCache()
	// Enabled + Set, then disable → Get should return false.
	cache.SetEnabled(true)
	if err := cache.Set("123456"); err != nil {
		t.Fatalf("cache.Set failed: %v", err)
	}
	cache.SetEnabled(false)

	// Verify the cache reports no hit.
	if _, ok := cache.Get(); ok {
		t.Fatal("expected cache miss when disabled")
	}
}

// TestMakePinReader_CacheHit_MultipleCalls verifies the closure can be called
// multiple times and continues to return the cached PIN.
func TestMakePinReader_CacheHit_MultipleCalls(t *testing.T) {
	cache := yubikey.NewPinCache()
	cache.SetEnabled(true)
	if err := cache.Set("654321"); err != nil {
		t.Fatalf("cache.Set failed: %v", err)
	}

	readPin := MakePinReader(nil, cache)

	for i := 0; i < 3; i++ {
		pin, err := readPin()
		if err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
		if pin != "654321" {
			t.Errorf("call %d: pin = %q, want %q", i, pin, "654321")
		}
	}
}

// TestMakePinReader_CacheCleared_NoHit verifies that after clearing the cache,
// the closure no longer returns a cached PIN.
func TestMakePinReader_CacheCleared_NoHit(t *testing.T) {
	cache := yubikey.NewPinCache()
	cache.SetEnabled(true)
	if err := cache.Set("123456"); err != nil {
		t.Fatalf("cache.Set failed: %v", err)
	}

	// Clear the cache — subsequent Get should miss.
	cache.Clear()

	if _, ok := cache.Get(); ok {
		t.Fatal("expected cache miss after Clear")
	}
}

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
			got := truncatePINToBytes(tt.in, pivMaxPINBytes)
			if got != tt.want {
				t.Errorf("truncatePINToBytes(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if len(got) > pivMaxPINBytes {
				t.Errorf("result %q is %d bytes, want <= %d", got, len(got), pivMaxPINBytes)
			}
			if !utf8.ValidString(got) {
				t.Errorf("result %q is not valid UTF-8", got)
			}
		})
	}
}

// TestTruncatePINToBytes_Idempotent verifies that re-truncating an
// already-truncated PIN is a no-op (the property applyPINByteCap relies on to
// avoid an OnChanged loop).
func TestTruncatePINToBytes_Idempotent(t *testing.T) {
	for _, s := range []string{"123456789", "café1234", "1234567é"} {
		once := truncatePINToBytes(s, pivMaxPINBytes)
		twice := truncatePINToBytes(once, pivMaxPINBytes)
		if twice != once {
			t.Errorf("truncatePINToBytes not idempotent for %q: once=%q twice=%q", s, once, twice)
		}
	}
}

// TestApplyPINByteCap verifies the OnChanged handler caps a real widget entry
// to 8 bytes without producing invalid UTF-8 or looping.
func TestApplyPINByteCap(t *testing.T) {
	test.NewApp()

	entry := widget.NewPasswordEntry()
	applyPINByteCap(entry)

	entry.SetText("123456789")
	if entry.Text != "12345678" {
		t.Errorf("after cap, entry.Text = %q, want %q", entry.Text, "12345678")
	}

	entry.SetText("café1234")
	if len(entry.Text) > pivMaxPINBytes || !utf8.ValidString(entry.Text) {
		t.Errorf("invariant violated: entry.Text = %q (%d bytes, valid=%v)",
			entry.Text, len(entry.Text), utf8.ValidString(entry.Text))
	}
	if entry.Text != "café123" {
		t.Errorf("after cap, entry.Text = %q, want %q", entry.Text, "café123")
	}
}

// TestProcessPINResult verifies the cancel/cap/cache semantics of the pure helper
// extracted from MakePinReader's post-dialog processing.
func TestProcessPINResult(t *testing.T) {
	t.Run("empty means cancelled, cache untouched", func(t *testing.T) {
		cache := yubikey.NewPinCache()
		cache.SetEnabled(true)

		pin, err := processPINResult("", cache)
		if err != ErrSigningCancelled {
			t.Errorf("err = %v, want ErrSigningCancelled", err)
		}
		if pin != "" {
			t.Errorf("pin = %q, want %q", pin, "")
		}
		if _, ok := cache.Get(); ok {
			t.Error("cache should be untouched on cancel")
		}
	})

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

// TestApplyPINByteCap_RuneSplitBoundary drives the utf8.RuneStart back-off end-to-end
// through the real widget's OnChanged/SetText: a trailing multibyte rune that would
// straddle the 8-byte limit must be dropped whole, not split.
func TestApplyPINByteCap_RuneSplitBoundary(t *testing.T) {
	test.NewApp()

	entry := widget.NewPasswordEntry()
	applyPINByteCap(entry)

	entry.SetText("1234567é")
	if entry.Text != "1234567" {
		t.Errorf("after cap, entry.Text = %q, want %q", entry.Text, "1234567")
	}
}

package gui

import (
	"testing"

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

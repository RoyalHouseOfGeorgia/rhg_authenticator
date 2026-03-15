package yubikey

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestNewPinCache_StartsDisabled(t *testing.T) {
	c := NewPinCache()
	defer c.Close()

	if c.Enabled() {
		t.Error("new PinCache should be disabled by default")
	}
	pin, ok := c.Get()
	if ok || pin != "" {
		t.Errorf("expected empty result from disabled cache, got %q, %v", pin, ok)
	}
}

func TestPinCache_SetAndGet(t *testing.T) {
	c := NewPinCache()
	defer c.Close()

	c.SetEnabled(true)
	if err := c.Set("123456"); err != nil {
		t.Fatal(err)
	}

	pin, ok := c.Get()
	if !ok {
		t.Fatal("expected cached PIN to be valid")
	}
	if pin != "123456" {
		t.Errorf("expected PIN %q, got %q", "123456", pin)
	}
}

func TestPinCache_DisableClearsPIN(t *testing.T) {
	c := NewPinCache()
	defer c.Close()

	c.SetEnabled(true)
	if err := c.Set("123456"); err != nil {
		t.Fatal(err)
	}

	c.SetEnabled(false)

	pin, ok := c.Get()
	if ok || pin != "" {
		t.Errorf("expected empty result after disable, got %q, %v", pin, ok)
	}
}

func TestPinCache_Clear(t *testing.T) {
	c := NewPinCache()
	defer c.Close()

	c.SetEnabled(true)
	if err := c.Set("123456"); err != nil {
		t.Fatal(err)
	}
	c.Clear()

	pin, ok := c.Get()
	if ok || pin != "" {
		t.Errorf("expected empty result after Clear, got %q, %v", pin, ok)
	}
}

func TestPinCache_Timeout(t *testing.T) {
	c := newPinCacheWithTimeout(50 * time.Millisecond)
	defer c.Close()

	c.SetEnabled(true)
	if err := c.Set("123456"); err != nil {
		t.Fatal(err)
	}

	// Wait for timeout to fire.
	time.Sleep(100 * time.Millisecond)

	pin, ok := c.Get()
	if ok || pin != "" {
		t.Errorf("expected PIN to be cleared after timeout, got %q, %v", pin, ok)
	}
}

func TestPinCache_TimeoutResetsOnSet(t *testing.T) {
	timeout := 100 * time.Millisecond
	c := newPinCacheWithTimeout(timeout)
	defer c.Close()

	c.SetEnabled(true)
	if err := c.Set("first"); err != nil {
		t.Fatal(err)
	}

	// Wait 60ms (more than half the timeout), then set again.
	time.Sleep(60 * time.Millisecond)
	if err := c.Set("second"); err != nil {
		t.Fatal(err)
	}

	// Wait another 60ms — total 120ms since first Set, but only 60ms since second Set.
	time.Sleep(60 * time.Millisecond)

	pin, ok := c.Get()
	if !ok {
		t.Fatal("expected PIN to still be valid after reset")
	}
	if pin != "second" {
		t.Errorf("expected PIN %q, got %q", "second", pin)
	}

	// Wait for timeout to expire from the second Set.
	time.Sleep(60 * time.Millisecond)

	pin, ok = c.Get()
	if ok || pin != "" {
		t.Errorf("expected PIN to be cleared after timeout, got %q, %v", pin, ok)
	}
}

func TestPinCache_ConcurrentAccess(t *testing.T) {
	c := newPinCacheWithTimeout(50 * time.Millisecond)
	defer c.Close()
	c.SetEnabled(true)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			_ = c.Set("pin123")
		}()
		go func() {
			defer wg.Done()
			c.Get()
		}()
		go func() {
			defer wg.Done()
			c.Clear()
		}()
	}
	wg.Wait()
}

func TestPinCache_SetDisabledIsNoop(t *testing.T) {
	c := NewPinCache()
	defer c.Close()

	// Cache is disabled by default; Set should be a no-op.
	if err := c.Set("123456"); err != nil {
		t.Fatal(err)
	}

	pin, ok := c.Get()
	if ok || pin != "" {
		t.Errorf("Set on disabled cache should be a no-op, got %q, %v", pin, ok)
	}
}

func TestPinCache_Close(t *testing.T) {
	c := NewPinCache()
	c.SetEnabled(true)
	if err := c.Set("123456"); err != nil {
		t.Fatal(err)
	}

	c.Close()

	pin, ok := c.Get()
	if ok || pin != "" {
		t.Errorf("expected empty result after Close, got %q, %v", pin, ok)
	}
}

func TestPinCache_DoubleClose(t *testing.T) {
	c := NewPinCache()
	c.SetEnabled(true)
	if err := c.Set("123456"); err != nil {
		t.Fatal(err)
	}

	// Double Close should not panic.
	c.Close()
	c.Close()
}

func TestPinCache_SetOverwritesExisting(t *testing.T) {
	c := NewPinCache()
	defer c.Close()
	c.SetEnabled(true)

	if err := c.Set("first"); err != nil {
		t.Fatal(err)
	}
	if err := c.Set("second"); err != nil {
		t.Fatal(err)
	}

	pin, ok := c.Get()
	if !ok {
		t.Fatal("expected cached PIN to be valid")
	}
	if pin != "second" {
		t.Errorf("expected PIN %q, got %q", "second", pin)
	}
}

func TestPinCache_EnableDisableEnable(t *testing.T) {
	c := NewPinCache()
	defer c.Close()

	c.SetEnabled(true)
	if err := c.Set("123456"); err != nil {
		t.Fatal(err)
	}
	c.SetEnabled(false)
	c.SetEnabled(true)

	// PIN should be gone after disable, even though we re-enabled.
	pin, ok := c.Get()
	if ok || pin != "" {
		t.Errorf("expected empty result after disable/enable cycle, got %q, %v", pin, ok)
	}

	// But new Set should work.
	if err := c.Set("654321"); err != nil {
		t.Fatal(err)
	}
	pin, ok = c.Get()
	if !ok || pin != "654321" {
		t.Errorf("expected PIN %q after re-enable Set, got %q, %v", "654321", pin, ok)
	}
}

func TestPinCache_ClearWithoutSet(t *testing.T) {
	c := NewPinCache()
	defer c.Close()
	c.SetEnabled(true)

	// Clear without ever setting should not panic.
	c.Clear()

	pin, ok := c.Get()
	if ok || pin != "" {
		t.Errorf("expected empty result, got %q, %v", pin, ok)
	}
}

func TestPinCacheTimeout_Constant(t *testing.T) {
	if PinCacheTimeout != 5*time.Minute {
		t.Errorf("PinCacheTimeout = %v, want 5m", PinCacheTimeout)
	}
}

func TestZeroBytes(t *testing.T) {
	buf := []byte{0x41, 0x42, 0x43}
	zeroBytes(buf)
	for i, b := range buf {
		if b != 0 {
			t.Errorf("byte %d = %x, want 0", i, b)
		}
	}
}

func TestZeroBytes_Empty(t *testing.T) {
	// Should not panic on empty slice.
	zeroBytes([]byte{})
	zeroBytes(nil)
}

func TestPinCache_SetMlockFailure(t *testing.T) {
	// Do NOT use t.Parallel() — mlockFunc is a package-level variable.
	origFunc := mlockFunc
	t.Cleanup(func() { mlockFunc = origFunc })

	mlockFunc = func(buf []byte) error {
		return fmt.Errorf("mlock: operation not permitted")
	}

	c := NewPinCache()
	defer c.Close()
	c.SetEnabled(true)

	err := c.Set("secret")
	if err == nil {
		t.Fatal("expected error from Set when mlock fails")
	}
	if got := err.Error(); got != "cannot secure memory: mlock: operation not permitted" {
		t.Errorf("unexpected error message: %s", got)
	}

	pin, ok := c.Get()
	if ok || pin != "" {
		t.Errorf("expected no cached PIN after mlock failure, got %q, %v", pin, ok)
	}
}

func TestPinCache_SetMlockFailure_PreservesOldCache(t *testing.T) {
	// Do NOT use t.Parallel() — mlockFunc is a package-level variable.
	origFunc := mlockFunc
	t.Cleanup(func() { mlockFunc = origFunc })

	c := NewPinCache()
	defer c.Close()
	c.SetEnabled(true)

	// Successfully cache a PIN first.
	if err := c.Set("original"); err != nil {
		t.Fatal(err)
	}

	// Now make mlock fail.
	mlockFunc = func(buf []byte) error {
		return fmt.Errorf("mlock: operation not permitted")
	}

	err := c.Set("replacement")
	if err == nil {
		t.Fatal("expected error from Set when mlock fails")
	}

	// Old cached PIN should still be available.
	pin, ok := c.Get()
	if !ok {
		t.Fatal("expected old cached PIN to still be valid")
	}
	if pin != "original" {
		t.Errorf("expected old PIN %q, got %q", "original", pin)
	}
}

func TestPinCache_SetEmptyPin(t *testing.T) {
	c := NewPinCache()
	defer c.Close()
	c.SetEnabled(true)

	err := c.Set("")
	if err != nil {
		t.Fatalf("Set empty PIN should return nil, got %v", err)
	}

	pin, ok := c.Get()
	if ok || pin != "" {
		t.Errorf("expected no cached PIN after empty Set, got %q, %v", pin, ok)
	}
}

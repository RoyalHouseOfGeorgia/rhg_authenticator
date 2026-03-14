package yubikey

import (
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
	c.Set("123456")

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
	c.Set("123456")

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
	c.Set("123456")
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
	c.Set("123456")

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
	c.Set("first")

	// Wait 60ms (more than half the timeout), then set again.
	time.Sleep(60 * time.Millisecond)
	c.Set("second")

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
			c.Set("pin123")
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
	c.Set("123456")

	pin, ok := c.Get()
	if ok || pin != "" {
		t.Errorf("Set on disabled cache should be a no-op, got %q, %v", pin, ok)
	}
}

func TestPinCache_Close(t *testing.T) {
	c := NewPinCache()
	c.SetEnabled(true)
	c.Set("123456")

	c.Close()

	pin, ok := c.Get()
	if ok || pin != "" {
		t.Errorf("expected empty result after Close, got %q, %v", pin, ok)
	}
}

func TestPinCache_DoubleClose(t *testing.T) {
	c := NewPinCache()
	c.SetEnabled(true)
	c.Set("123456")

	// Double Close should not panic.
	c.Close()
	c.Close()
}

func TestPinCache_SetOverwritesExisting(t *testing.T) {
	c := NewPinCache()
	defer c.Close()
	c.SetEnabled(true)

	c.Set("first")
	c.Set("second")

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
	c.Set("123456")
	c.SetEnabled(false)
	c.SetEnabled(true)

	// PIN should be gone after disable, even though we re-enabled.
	pin, ok := c.Get()
	if ok || pin != "" {
		t.Errorf("expected empty result after disable/enable cycle, got %q, %v", pin, ok)
	}

	// But new Set should work.
	c.Set("654321")
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

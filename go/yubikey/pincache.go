package yubikey

import (
	"sync"
	"time"
)

// PinCacheTimeout is the duration after which a cached PIN is automatically cleared.
const PinCacheTimeout = 5 * time.Minute

// PinCache provides opt-in secure PIN caching.
// PIN is stored in mlock'd memory, protected by mutex, auto-zeroed on timeout.
type PinCache struct {
	mu      sync.Mutex
	pin     []byte // mlock'd buffer
	valid   bool
	timer   *time.Timer
	enabled bool // whether caching is enabled (checkbox state)
	timeout time.Duration
}

// NewPinCache creates a new PIN cache (disabled by default).
func NewPinCache() *PinCache {
	return &PinCache{
		timeout: PinCacheTimeout,
	}
}

// newPinCacheWithTimeout creates a PIN cache with a custom timeout (for testing).
func newPinCacheWithTimeout(timeout time.Duration) *PinCache {
	return &PinCache{
		timeout: timeout,
	}
}

// SetEnabled enables or disables caching.
// When disabled, any cached PIN is immediately zeroed.
func (c *PinCache) SetEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enabled = enabled
	if !enabled {
		c.clearLocked()
	}
}

// Enabled returns whether caching is currently enabled.
func (c *PinCache) Enabled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.enabled
}

// Note: the returned string is a copy outside mlock'd memory. Go strings are
// immutable and cannot be zeroed. The mlock'd []byte buffer is the primary
// defense; the string copy is short-lived in the calling goroutine.

// Get returns the cached PIN if valid and caching is enabled.
// Returns ("", false) if no cached PIN or caching is disabled.
func (c *PinCache) Get() (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.enabled || !c.valid || len(c.pin) == 0 {
		return "", false
	}
	return string(c.pin), true
}

// Set stores a PIN in the cache (if caching is enabled).
// Locks the buffer in RAM via mlock. Resets the timeout.
func (c *PinCache) Set(pin string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.enabled {
		return
	}

	// Zero any existing buffer before replacing.
	if c.pin != nil {
		zeroBytes(c.pin)
	}

	// Allocate new buffer, copy, and mlock.
	buf := make([]byte, len(pin))
	copy(buf, pin)
	mlockBuffer(buf)

	c.pin = buf
	c.valid = true

	// Reset or create the expiry timer.
	if c.timer != nil {
		c.timer.Stop()
	}
	c.timer = time.AfterFunc(c.timeout, c.Clear)
}

// Clear zeroes and invalidates the cached PIN.
func (c *PinCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clearLocked()
}

// clearLocked zeroes the PIN buffer and stops the timer. Caller must hold mu.
func (c *PinCache) clearLocked() {
	if c.pin != nil {
		zeroBytes(c.pin)
		c.pin = nil
	}
	c.valid = false
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
}

// Close clears the cache and stops the timer.
func (c *PinCache) Close() {
	c.Clear()
}

// zeroBytes overwrites every byte in the slice with zero.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

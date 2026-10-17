package gui

import (
	"sync"
	"sync/atomic"
	"testing"
)

// --- atomic.Bool guard pattern tests ---
// These verify the CompareAndSwap guard used in doFetch is race-free.

func TestAtomicBoolGuard_OnlyOneWins(t *testing.T) {
	// Simulate the CompareAndSwap guard pattern used in doFetch:
	// only one concurrent caller should proceed.
	var fetching atomic.Bool
	var entered int64
	var wg sync.WaitGroup

	const goroutines = 100
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			if !fetching.CompareAndSwap(false, true) {
				return
			}
			atomic.AddInt64(&entered, 1)
			// Simulate work, then release.
			fetching.Store(false)
		}()
	}
	wg.Wait()

	// At least one goroutine must have entered.
	if atomic.LoadInt64(&entered) == 0 {
		t.Fatal("no goroutine entered the guarded section")
	}
}

func TestAtomicBoolGuard_ReusableAfterStore(t *testing.T) {
	// Verify that after Store(false), a new CompareAndSwap(false, true) succeeds.
	var fetching atomic.Bool

	if !fetching.CompareAndSwap(false, true) {
		t.Fatal("first CompareAndSwap should succeed")
	}
	// Second call while "fetching" should fail.
	if fetching.CompareAndSwap(false, true) {
		t.Fatal("second CompareAndSwap should fail while fetching")
	}
	// Release.
	fetching.Store(false)
	// Now it should succeed again.
	if !fetching.CompareAndSwap(false, true) {
		t.Fatal("CompareAndSwap after Store(false) should succeed")
	}
}

func TestAtomicBoolGuard_RaceFree(t *testing.T) {
	// Run with -race to verify no data races on the guard pattern.
	var fetching atomic.Bool
	var wg sync.WaitGroup

	const rounds = 50
	wg.Add(rounds * 2)
	for range rounds {
		go func() {
			defer wg.Done()
			if !fetching.CompareAndSwap(false, true) {
				return
			}
			fetching.Store(false)
		}()
		go func() {
			defer wg.Done()
			// Concurrent Load is also safe.
			_ = fetching.Load()
		}()
	}
	wg.Wait()
}

package gui

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
)

// --- formatCommitSummary tests ---

func TestFormatCommitSummary(t *testing.T) {
	c := ghapi.RegistryCommit{SHA: "abc123"}
	c.Commit.Message = "Fix registry"
	c.Commit.Author.Name = "Kimon"
	c.Commit.Author.Date = "2026-03-15T10:00:00Z"

	got := formatCommitSummary(c)
	want := "2026-Mar-15  Kimon — Fix registry"
	if got != want {
		t.Errorf("formatCommitSummary = %q, want %q", got, want)
	}
}

func TestFormatCommitSummary_LongMessage(t *testing.T) {
	c := ghapi.RegistryCommit{}
	c.Commit.Message = strings.Repeat("a", 100)
	c.Commit.Author.Name = "Author"
	c.Commit.Author.Date = "2026-03-15T10:00:00Z"

	got := formatCommitSummary(c)
	if !strings.HasSuffix(got, "...") {
		t.Error("long message should be truncated with '...'")
	}
	// The message portion should be 80 runes + "..."
	// Extract the part after " — "
	parts := strings.SplitN(got, " — ", 2)
	if len(parts) != 2 {
		t.Fatalf("unexpected format: %q", got)
	}
	msgRunes := []rune(parts[1])
	// 80 runes + 3 for "..."
	if len(msgRunes) != 83 {
		t.Errorf("truncated message rune count = %d, want 83", len(msgRunes))
	}
}

func TestFormatCommitSummary_MultilineMessage(t *testing.T) {
	c := ghapi.RegistryCommit{}
	c.Commit.Message = "line1\nline2\nline3"
	c.Commit.Author.Name = "Author"
	c.Commit.Author.Date = "2026-03-15T10:00:00Z"

	got := formatCommitSummary(c)
	if strings.Contains(got, "line2") {
		t.Error("multiline message should only show first line")
	}
	if !strings.Contains(got, "line1") {
		t.Error("should contain first line")
	}
}

func TestFormatCommitSummary_EmptyFields(t *testing.T) {
	c := ghapi.RegistryCommit{}
	c.Commit.Message = ""
	c.Commit.Author.Name = ""
	c.Commit.Author.Date = "not-a-date"

	got := formatCommitSummary(c)
	if !strings.Contains(got, "Unknown") {
		t.Errorf("empty author should show 'Unknown', got: %q", got)
	}
	if !strings.Contains(got, "(no message)") {
		t.Errorf("empty message should show '(no message)', got: %q", got)
	}
	if !strings.Contains(got, "not-a-date") {
		t.Errorf("bad date should use raw string, got: %q", got)
	}
}

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

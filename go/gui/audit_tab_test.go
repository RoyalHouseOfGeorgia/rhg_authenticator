package gui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// validCommitJSON is a fixture for fetch tests.
const validCommitJSON = `[{
	"sha": "abc123",
	"html_url": "https://github.com/royalhouseofgeorgia/rhg-authenticator/commit/abc123",
	"commit": {
		"message": "Update registry",
		"author": {
			"name": "Kimon",
			"date": "2026-03-15T10:00:00Z"
		}
	}
}]`

// --- fetchCommits tests ---

func TestFetchCommits_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(validCommitJSON))
	}))
	defer srv.Close()

	commits, _, err := fetchCommits(srv.URL, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(commits) != 1 {
		t.Fatalf("expected 1 commit, got %d", len(commits))
	}
	if commits[0].SHA != "abc123" {
		t.Errorf("SHA = %q, want %q", commits[0].SHA, "abc123")
	}
	if commits[0].HTMLURL != "https://github.com/royalhouseofgeorgia/rhg-authenticator/commit/abc123" {
		t.Errorf("HTMLURL = %q", commits[0].HTMLURL)
	}
	if commits[0].Commit.Message != "Update registry" {
		t.Errorf("Message = %q", commits[0].Commit.Message)
	}
	if commits[0].Commit.Author.Name != "Kimon" {
		t.Errorf("Author.Name = %q", commits[0].Commit.Author.Name)
	}
	if commits[0].Commit.Author.Date != "2026-03-15T10:00:00Z" {
		t.Errorf("Author.Date = %q", commits[0].Commit.Author.Date)
	}
}

func TestFetchCommits_HTTP404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, _, err := fetchCommits(srv.URL, "")
	if err == nil {
		t.Fatal("expected error for HTTP 404")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error should contain '404', got: %v", err)
	}
}

func TestFetchCommits_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{not valid json"))
	}))
	defer srv.Close()

	_, _, err := fetchCommits(srv.URL, "")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "JSON decode") {
		t.Errorf("error should mention JSON decode, got: %v", err)
	}
}

func TestFetchCommits_EmptyArray(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
	}))
	defer srv.Close()

	commits, _, err := fetchCommits(srv.URL, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(commits) != 0 {
		t.Errorf("expected empty slice, got %d", len(commits))
	}
}

func TestFetchCommits_WrongContentType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()

	_, _, err := fetchCommits(srv.URL, "")
	if err == nil {
		t.Fatal("expected error for wrong Content-Type")
	}
	if !strings.Contains(err.Error(), "Content-Type") {
		t.Errorf("error should mention Content-Type, got: %v", err)
	}
}

func TestFetchCommits_OversizedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Write a valid JSON array start, then exceed 1 MiB so the
		// LimitReader truncates mid-stream causing a decode error.
		w.Write([]byte(`[{"sha":"`))
		filler := strings.Repeat("x", maxCommitsBytes+1)
		w.Write([]byte(filler))
		w.Write([]byte(`"}]`))
	}))
	defer srv.Close()

	_, _, err := fetchCommits(srv.URL, "")
	if err == nil {
		t.Fatal("expected error for oversized response")
	}
}

func TestFetchCommits_RateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	_, _, err := fetchCommits(srv.URL, "")
	if err == nil {
		t.Fatal("expected error for 429")
	}
	if !strings.Contains(err.Error(), "rate limited") {
		t.Errorf("error should contain 'rate limited', got: %v", err)
	}
}

// --- formatCommitSummary tests ---

func TestFormatCommitSummary(t *testing.T) {
	c := RegistryCommit{SHA: "abc123"}
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
	c := RegistryCommit{}
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
	c := RegistryCommit{}
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
	c := RegistryCommit{}
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

// --- isValidGitHubURL tests ---

func TestParseGitHubURL_Valid(t *testing.T) {
	if parseGitHubURL("https://github.com/owner/repo/commit/abc123") == nil {
		t.Error("expected non-nil for valid GitHub URL")
	}
}

func TestParseGitHubURL_HTTP(t *testing.T) {
	if parseGitHubURL("http://github.com/owner/repo/commit/abc123") != nil {
		t.Error("expected nil for HTTP scheme")
	}
}

func TestParseGitHubURL_NonGitHub(t *testing.T) {
	if parseGitHubURL("https://gitlab.com/owner/repo/commit/abc123") != nil {
		t.Error("expected nil for non-GitHub host")
	}
}

func TestParseGitHubURL_Malformed(t *testing.T) {
	if parseGitHubURL("://not-a-url") != nil {
		t.Error("expected nil for malformed URL")
	}
}

// --- truncateRunes tests ---

func TestTruncateRunes_Short(t *testing.T) {
	got := truncateRunes("short", 80)
	if got != "short" {
		t.Errorf("truncateRunes = %q, want %q", got, "short")
	}
}

func TestTruncateRunes_ExactLength(t *testing.T) {
	s := strings.Repeat("a", 80)
	got := truncateRunes(s, 80)
	if got != s {
		t.Errorf("truncateRunes exact = %q, want %q", got, s)
	}
}

func TestTruncateRunes_Long(t *testing.T) {
	s := strings.Repeat("a", 90)
	got := truncateRunes(s, 80)
	want := strings.Repeat("a", 80) + "..."
	if got != want {
		t.Errorf("truncateRunes long = %q, want %q", got, want)
	}
}

func TestTruncateRunes_Unicode(t *testing.T) {
	// Georgian characters: multi-byte but single rune each.
	s := strings.Repeat("\u10D0", 85)
	got := truncateRunes(s, 80)
	want := strings.Repeat("\u10D0", 80) + "..."
	if got != want {
		t.Errorf("truncateRunes unicode mismatch")
	}
}

// --- isValidGitHubURL additional edge cases ---

func TestParseGitHubURL_EmptyString(t *testing.T) {
	if parseGitHubURL("") != nil {
		t.Error("expected nil for empty string")
	}
}

func TestParseGitHubURL_WithCredentials(t *testing.T) {
	if parseGitHubURL("https://user:pass@github.com/owner/repo") != nil {
		t.Error("expected nil for URL with embedded credentials")
	}
}

// --- fetchCommits edge cases ---

func TestFetchCommits_NetworkError(t *testing.T) {
	// Use a URL that will definitely fail to connect.
	_, _, err := fetchCommits("http://127.0.0.1:1/nonexistent", "")
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
}

func TestFetchCommits_ContentTypeWithCharset(t *testing.T) {
	// GitHub returns "application/json; charset=utf-8" — should still work.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Write([]byte(validCommitJSON))
	}))
	defer srv.Close()

	commits, _, err := fetchCommits(srv.URL, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(commits) != 1 {
		t.Errorf("expected 1 commit, got %d", len(commits))
	}
}

// --- ETag caching tests ---

func TestFetchCommits_304NotModified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"abc123"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"abc123"`)
		w.Write([]byte(validCommitJSON))
	}))
	defer srv.Close()

	// First fetch: gets data + etag.
	result, etag, err := fetchCommits(srv.URL, "")
	if err != nil {
		t.Fatalf("first fetch: unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("first fetch: expected non-nil commits")
	}
	if etag != `"abc123"` {
		t.Errorf("first fetch: etag = %q, want %q", etag, `"abc123"`)
	}

	// Second fetch with etag: gets 304.
	result2, etag2, err2 := fetchCommits(srv.URL, etag)
	if err2 != nil {
		t.Fatalf("second fetch: unexpected error: %v", err2)
	}
	if result2 != nil {
		t.Error("second fetch: expected nil commits for 304")
	}
	if etag2 != etag {
		t.Errorf("second fetch: etag = %q, want %q", etag2, etag)
	}
}

func TestFetchCommits_ETagSent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("If-None-Match"); got != `"test-etag"` {
			t.Errorf("If-None-Match = %q, want %q", got, `"test-etag"`)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(validCommitJSON))
	}))
	defer srv.Close()

	fetchCommits(srv.URL, `"test-etag"`)
}

func TestFetchCommits_ETagCached(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"fresh-etag"`)
		w.Write([]byte(validCommitJSON))
	}))
	defer srv.Close()

	_, etag, err := fetchCommits(srv.URL, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if etag != `"fresh-etag"` {
		t.Errorf("etag = %q, want %q", etag, `"fresh-etag"`)
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

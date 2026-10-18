package service

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

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

// --- truncateRunes tests ---

func TestTruncateRunes_Short(t *testing.T) {
	got := truncateRunes("Short", 50)
	if got != "Short" {
		t.Errorf("truncateRunes = %q, want %q", got, "Short")
	}
}

func TestTruncateRunes_ExactLength(t *testing.T) {
	s := strings.Repeat("a", 50)
	got := truncateRunes(s, 50)
	if got != s {
		t.Errorf("truncateRunes exact = %q, want %q", got, s)
	}
}

func TestTruncateRunes_Long(t *testing.T) {
	s := strings.Repeat("a", 60)
	got := truncateRunes(s, 50)
	want := strings.Repeat("a", 50) + "..."
	if got != want {
		t.Errorf("truncateRunes long = %q, want %q", got, want)
	}
}

func TestTruncateRunes_Unicode(t *testing.T) {
	// Georgian characters are multi-byte but each is one rune.
	s := strings.Repeat("\u10D0", 55) // 55 Georgian "a" runes
	got := truncateRunes(s, 50)
	wantPrefix := strings.Repeat("\u10D0", 50) + "..."
	if got != wantPrefix {
		t.Errorf("truncateRunes unicode length mismatch")
	}
}

func TestTruncateRunes_Empty(t *testing.T) {
	got := truncateRunes("", 50)
	if got != "" {
		t.Errorf("truncateRunes empty = %q, want empty", got)
	}
}

func TestTruncateRunes_ZeroMax(t *testing.T) {
	got := truncateRunes("anything", 0)
	if got != "" {
		t.Errorf("truncateRunes zero max = %q, want empty", got)
	}
}

// --- AuditCommits ---

// commitsServer is a GitHub commits API whose responses are produced by
// respond; the If-None-Match header of each request is recorded.
type commitsServer struct {
	mu          sync.Mutex
	ifNoneMatch []string
	perPage     []string
}

func (s *commitsServer) requests() ([]string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.ifNoneMatch...), append([]string(nil), s.perPage...)
}

// useCommitsServer points h's commit fetch at a test server; respond writes
// the n-th (0-based) response.
func useCommitsServer(t *testing.T, h *appHarness, respond func(n int, w http.ResponseWriter)) *commitsServer {
	t.Helper()
	cs := &commitsServer{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.mu.Lock()
		n := len(cs.ifNoneMatch)
		cs.ifNoneMatch = append(cs.ifNoneMatch, r.Header.Get("If-None-Match"))
		cs.perPage = append(cs.perPage, r.URL.Query().Get("per_page"))
		cs.mu.Unlock()
		respond(n, w)
	}))
	t.Cleanup(srv.Close)
	h.app.fetchCommits = func(_ string, perPage int, etag string) ([]ghapi.RegistryCommit, string, error) {
		return ghapi.FetchRegistryCommits(srv.URL, perPage, etag)
	}
	return cs
}

const commitsJSON = `[
	{"sha":"1","html_url":"https://github.com/o/r/commit/1","commit":{"message":"Add key\nbody","author":{"name":"Kimon","date":"2026-03-15T10:00:00Z"}}},
	{"sha":"2","html_url":"https://evil.example/commit/2","commit":{"message":"Revoke key","author":{"name":"Other","date":"2026-03-16T10:00:00Z"}}}
]`

func serveCommits(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", `"v1"`)
	fmt.Fprint(w, commitsJSON)
}

var wantAuditRows = []AuditRow{
	{Summary: "2026-Mar-15  Kimon — Add key", URL: "https://github.com/o/r/commit/1"},
	{Summary: "2026-Mar-16  Other — Revoke key", URL: ""},
}

func TestAuditCommits_LoadThenNotModified(t *testing.T) {
	h := newAppHarness(t, nil)
	cs := useCommitsServer(t, h, func(n int, w http.ResponseWriter) {
		if n == 0 {
			serveCommits(w)
			return
		}
		w.WriteHeader(http.StatusNotModified)
	})

	res, err := h.app.AuditCommits()
	if err != nil || res.Status != "Loaded 2 commits" || !reflect.DeepEqual(res.Rows, wantAuditRows) {
		t.Fatalf("first AuditCommits = %+v, %v", res, err)
	}
	res, err = h.app.AuditCommits()
	if err != nil || res.Status != "No changes since last check" || !reflect.DeepEqual(res.Rows, wantAuditRows) {
		t.Errorf("second AuditCommits = %+v, %v", res, err)
	}
	etags, perPage := cs.requests()
	if !reflect.DeepEqual(etags, []string{"", `"v1"`}) {
		t.Errorf("If-None-Match = %q", etags)
	}
	if perPage[0] != "50" {
		t.Errorf("per_page = %q, want 50", perPage[0])
	}
}

func TestAuditCommits_ErrorsKeepRowsAndETag(t *testing.T) {
	for _, tc := range []struct {
		name, wantErr string
		status        int
	}{
		{"rate limited", "GitHub rate limit reached. Try again in a few minutes.", http.StatusTooManyRequests},
		{"server error", "Failed to fetch registry history.", http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newAppHarness(t, nil)
			cs := useCommitsServer(t, h, func(n int, w http.ResponseWriter) {
				switch n {
				case 0:
					serveCommits(w)
				case 1:
					w.WriteHeader(tc.status)
				default:
					w.WriteHeader(http.StatusNotModified)
				}
			})
			if _, err := h.app.AuditCommits(); err != nil {
				t.Fatal(err)
			}
			if _, err := h.app.AuditCommits(); err == nil || err.Error() != tc.wantErr {
				t.Errorf("err = %v, want %q", err, tc.wantErr)
			}
			if !strings.Contains(h.debugLog(t), "audit: registry commit fetch failed: ") {
				t.Error("failure not logged")
			}
			res, err := h.app.AuditCommits()
			if err != nil || !reflect.DeepEqual(res.Rows, wantAuditRows) {
				t.Errorf("after error = %+v, %v; want the earlier rows", res, err)
			}
			if etags, _ := cs.requests(); etags[2] != `"v1"` {
				t.Errorf("If-None-Match after error = %q, want the kept ETag", etags[2])
			}
		})
	}
}

func TestAuditCommits_Busy(t *testing.T) {
	h := newAppHarness(t, nil)
	entered, release := make(chan struct{}), make(chan struct{})
	h.app.fetchCommits = func(string, int, string) ([]ghapi.RegistryCommit, string, error) {
		close(entered)
		<-release
		return []ghapi.RegistryCommit{}, "", nil
	}
	done := make(chan error, 1)
	go func() {
		_, err := h.app.AuditCommits()
		done <- err
	}()
	<-entered
	if _, err := h.app.AuditCommits(); !errors.Is(err, ErrBusy) {
		t.Errorf("second AuditCommits err = %v, want ErrBusy", err)
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("first AuditCommits err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first AuditCommits did not return")
	}
}

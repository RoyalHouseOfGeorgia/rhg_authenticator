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
	cases := []struct {
		name                  string
		sha                   string
		message, author, date string
		want                  string
	}{
		{"basic", "abc123", "Fix registry", "Kimon", "2026-03-15T10:00:00Z", "2026-Mar-15  Kimon — Fix registry"},
		{"long message truncated to 80 runes plus ellipsis", "", strings.Repeat("a", 100), "Author", "2026-03-15T10:00:00Z", "2026-Mar-15  Author — " + strings.Repeat("a", 80) + "..."},
		{"multiline message shows only the first line", "", "line1\nline2\nline3", "Author", "2026-03-15T10:00:00Z", "2026-Mar-15  Author — line1"},
		{"empty fields fall back and a bad date is shown raw", "", "", "", "not-a-date", "not-a-date  Unknown — (no message)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := ghapi.RegistryCommit{SHA: tc.sha}
			c.Commit.Message = tc.message
			c.Commit.Author.Name = tc.author
			c.Commit.Author.Date = tc.date
			if got := formatCommitSummary(c); got != tc.want {
				t.Errorf("formatCommitSummary = %q, want %q", got, tc.want)
			}
		})
	}
}

// --- truncateRunes tests ---

func TestTruncateRunes(t *testing.T) {
	cases := []struct {
		name   string
		s      string
		maxLen int
		want   string
	}{
		{"short", "Short", 50, "Short"},
		{"exact length", strings.Repeat("a", 50), 50, strings.Repeat("a", 50)},
		{"long", strings.Repeat("a", 60), 50, strings.Repeat("a", 50) + "..."},
		// Georgian characters are multi-byte but each is one rune.
		{"unicode", strings.Repeat("\u10D0", 55), 50, strings.Repeat("\u10D0", 50) + "..."},
		{"zero max", "anything", 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := truncateRunes(tc.s, tc.maxLen); got != tc.want {
				t.Errorf("truncateRunes(%q, %d) = %q, want %q", tc.s, tc.maxLen, got, tc.want)
			}
		})
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

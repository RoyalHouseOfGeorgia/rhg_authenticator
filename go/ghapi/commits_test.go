package ghapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// testCommitServer creates a test server for commit tests.
// Returns the server (caller must defer srv.Close()).
func testCommitServer(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(handler)
}

func TestFetchRegistryCommits_Success(t *testing.T) {
	commits := []RegistryCommit{
		{SHA: "abc123", HTMLURL: "https://github.com/commit/abc123"},
		{SHA: "def456", HTMLURL: "https://github.com/commit/def456"},
	}
	commits[0].Commit.Message = "Update registry"
	commits[0].Commit.Author.Name = "Alice"
	commits[0].Commit.Author.Date = "2026-03-20T10:00:00Z"
	commits[1].Commit.Message = "Add new key"
	commits[1].Commit.Author.Name = "Bob"
	commits[1].Commit.Author.Date = "2026-03-19T09:00:00Z"

	body, _ := json.Marshal(commits)

	ts := testCommitServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"etag123"`)
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	})
	defer ts.Close()

	result, etag, err := FetchRegistryCommits(ts.URL, 50, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if etag != `"etag123"` {
		t.Errorf("etag = %q, want %q", etag, `"etag123"`)
	}
	if len(result) != 2 {
		t.Fatalf("got %d commits, want 2", len(result))
	}
	if result[0].SHA != "abc123" {
		t.Errorf("result[0].SHA = %q, want %q", result[0].SHA, "abc123")
	}
	if result[0].Commit.Author.Name != "Alice" {
		t.Errorf("result[0].Commit.Author.Name = %q, want %q", result[0].Commit.Author.Name, "Alice")
	}
	if result[1].SHA != "def456" {
		t.Errorf("result[1].SHA = %q, want %q", result[1].SHA, "def456")
	}
}

func TestFetchRegistryCommits_ETag304(t *testing.T) {
	ts := testCommitServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"etag-old"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		t.Error("expected If-None-Match header")
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	result, etag, err := FetchRegistryCommits(ts.URL, 50, `"etag-old"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil commits on 304, got %d", len(result))
	}
	if etag != `"etag-old"` {
		t.Errorf("etag = %q, want %q", etag, `"etag-old"`)
	}
}

func TestFetchRegistryCommits_NetworkError(t *testing.T) {
	// Create a server and immediately close it to simulate network error.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedURL := ts.URL
	ts.Close()

	_, _, err := FetchRegistryCommits(closedURL, 50, "")
	if err == nil {
		t.Fatal("expected error for network failure")
	}
	if !strings.Contains(err.Error(), "request failed") {
		t.Errorf("error = %q, want it to contain 'request failed'", err.Error())
	}
}

func TestFetchRegistryCommits_InvalidJSON(t *testing.T) {
	ts := testCommitServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{invalid json`))
	})
	defer ts.Close()

	_, _, err := FetchRegistryCommits(ts.URL, 50, "")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "JSON decode") {
		t.Errorf("error = %q, want it to contain 'JSON decode'", err.Error())
	}
}

func TestFetchRegistryCommits_RateLimit(t *testing.T) {
	ts := testCommitServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	})
	defer ts.Close()

	_, _, err := FetchRegistryCommits(ts.URL, 50, "")
	if err == nil {
		t.Fatal("expected error for rate limit")
	}
	if !IsRateLimited(err) {
		t.Errorf("expected IsRateLimited(err) to be true, got error: %v", err)
	}
}

func TestFetchRegistryCommits_UnexpectedContentType(t *testing.T) {
	ts := testCommitServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html>oops</html>"))
	})
	defer ts.Close()

	_, _, err := FetchRegistryCommits(ts.URL, 10, "")
	if err == nil {
		t.Fatal("expected error for unexpected Content-Type")
	}
	if !strings.Contains(err.Error(), "unexpected Content-Type") {
		t.Errorf("error = %q, want it to contain 'unexpected Content-Type'", err.Error())
	}
}

func TestFetchRegistryCommits_NonOKStatus(t *testing.T) {
	ts := testCommitServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer ts.Close()

	_, _, err := FetchRegistryCommits(ts.URL, 10, "")
	if err == nil {
		t.Fatal("expected error for 500 status")
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("error = %q, want it to contain 'HTTP 500'", err.Error())
	}
}


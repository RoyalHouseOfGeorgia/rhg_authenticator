package ghapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

// --- SafeRedirect tests ---

func TestSafeRedirect_AllowsHTTPS(t *testing.T) {
	target, _ := url.Parse("https://cdn.example.com/path")
	req := &http.Request{URL: target}
	via := []*http.Request{{}}
	if err := SafeRedirect(req, via); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSafeRedirect_RejectsHTTP(t *testing.T) {
	target, _ := url.Parse("http://evil.com/path")
	req := &http.Request{URL: target}
	via := []*http.Request{{}}
	if err := SafeRedirect(req, via); err == nil {
		t.Fatal("expected error for HTTP redirect")
	}
}

func TestSafeRedirect_RejectsExcessiveRedirects(t *testing.T) {
	target, _ := url.Parse("https://example.com/path")
	req := &http.Request{URL: target}
	via := make([]*http.Request, 10)
	for i := range via {
		via[i] = &http.Request{}
	}
	if err := SafeRedirect(req, via); err == nil {
		t.Fatal("expected error after 10 redirects")
	}
}

// --- NewClient ---

func TestNewClient(t *testing.T) {
	c := NewClient("tok_abc")
	if c.token != "tok_abc" {
		t.Errorf("Token = %q, want %q", c.token, "tok_abc")
	}
	if c.Owner != DefaultOwner {
		t.Errorf("Owner = %q, want %q", c.Owner, DefaultOwner)
	}
	if c.Repo != DefaultRepo {
		t.Errorf("Repo = %q, want %q", c.Repo, DefaultRepo)
	}
	if c.HTTPClient == nil {
		t.Fatal("HTTPClient is nil")
	}
	if c.HTTPClient.Timeout != clientTimeout {
		t.Errorf("Timeout = %v, want %v", c.HTTPClient.Timeout, clientTimeout)
	}
}

// --- doJSON tests ---

func TestDoJSON_AuthHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		want := "Bearer test-token-123"
		if got != want {
			t.Errorf("Authorization = %q, want %q", got, want)
		}
		accept := r.Header.Get("Accept")
		if accept != "application/vnd.github+json" {
			t.Errorf("Accept = %q, want application/vnd.github+json", accept)
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	c := newTestClient(srv, "test-token-123")
	err := c.doJSON(context.Background(), http.MethodGet, "/test", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDoJSON_ResponseSizeLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Write just over maxResponseBytes.
		w.WriteHeader(200)
		data := make([]byte, maxResponseBytes+1)
		for i := range data {
			data[i] = 'x'
		}
		w.Write(data)
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	err := c.doJSON(context.Background(), http.MethodGet, "/test", nil, nil)
	if err == nil {
		t.Fatal("expected error for oversized response")
	}
	if !strings.Contains(err.Error(), "exceeded 2 MiB") {
		t.Errorf("error = %q, want to contain 'exceeded 2 MiB'", err.Error())
	}
}

func TestDoJSON_401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte(`{"message": "Bad credentials"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	err := c.doJSON(context.Background(), http.MethodGet, "/test", nil, nil)
	if !IsUnauthorized(err) {
		t.Errorf("IsUnauthorized = false, want true; err = %v", err)
	}
}

func TestDoJSON_403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte(`{"message": "Forbidden"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	err := c.doJSON(context.Background(), http.MethodGet, "/test", nil, nil)
	if !IsForbidden(err) {
		t.Errorf("IsForbidden = false, want true; err = %v", err)
	}
}

func TestDoJSON_429(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	err := c.doJSON(context.Background(), http.MethodGet, "/test", nil, nil)
	if !IsRateLimited(err) {
		t.Errorf("IsRateLimited = false, want true; err = %v", err)
	}
	if !strings.Contains(err.Error(), "rate limit exceeded") {
		t.Errorf("error = %q, want to contain 'rate limit exceeded'", err.Error())
	}
}

// --- getRef ---

func TestGetRef_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/git/refs/heads/main") {
			t.Errorf("path = %s, want suffix /git/refs/heads/main", r.URL.Path)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"ref": "refs/heads/main", "object": {"sha": "abc123def456"}}`))
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	sha, err := c.getRef(context.Background(), "heads/main")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sha != "abc123def456" {
		t.Errorf("SHA = %q, want %q", sha, "abc123def456")
	}
}

func TestGetRef_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte(`{"message": "Not Found"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	_, err := c.getRef(context.Background(), "heads/nonexistent")
	if err == nil {
		t.Fatal("expected error for 404")
	}
	var ae *APIError
	if !isAPIError(err, 404, &ae) {
		t.Errorf("expected APIError 404, got %v", err)
	}
}

// --- updateContents ---

func TestUpdateContents_Base64Encoding(t *testing.T) {
	rawContent := []byte(`{"keys": [{"test": true}]}`)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %s, want PUT", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		var req map[string]string
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("unmarshal request body: %v", err)
		}
		decoded, err := base64.StdEncoding.DecodeString(req["content"])
		if err != nil {
			t.Fatalf("base64 decode: %v", err)
		}
		if string(decoded) != string(rawContent) {
			t.Errorf("decoded content = %q, want %q", decoded, rawContent)
		}
		if req["branch"] != "test-branch" {
			t.Errorf("branch = %q, want %q", req["branch"], "test-branch")
		}
		if req["sha"] != "file-sha-123" {
			t.Errorf("sha = %q, want %q", req["sha"], "file-sha-123")
		}
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	err := c.updateContents(context.Background(), "path/to/file.json", "test-branch", rawContent, "file-sha-123", "update msg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- CreateRegistryPR ---

func TestCreateRegistryPR_Success(t *testing.T) {
	var callSequence []string
	content := []byte(`{"keys": []}`)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/forks"):
			callSequence = append(callSequence, "forkRepo")
			w.WriteHeader(202)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/repos/testuser/"):
			if strings.Contains(r.URL.Path, "/git/refs/heads/main") {
				callSequence = append(callSequence, "getRef")
				w.WriteHeader(200)
				json.NewEncoder(w).Encode(map[string]any{
					"ref":    "refs/heads/main",
					"object": map[string]string{"sha": "main-sha-000"},
				})
			} else if strings.Contains(r.URL.Path, "/contents/") {
				callSequence = append(callSequence, "getContents")
				w.WriteHeader(200)
				json.NewEncoder(w).Encode(map[string]string{"sha": "file-sha-abc"})
			} else {
				// waitForFork: GET /repos/testuser/rhg_authenticator
				callSequence = append(callSequence, "waitForFork")
				w.WriteHeader(200)
				w.Write([]byte(`{}`))
			}

		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/repos/testuser/") && strings.HasSuffix(r.URL.Path, "/merge-upstream"):
			callSequence = append(callSequence, "syncFork")
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/repos/testuser/") && strings.HasSuffix(r.URL.Path, "/git/refs"):
			callSequence = append(callSequence, "createRef")
			body, _ := io.ReadAll(r.Body)
			var req map[string]string
			json.Unmarshal(body, &req)
			if req["sha"] != "main-sha-000" {
				t.Errorf("createRef sha = %q, want main-sha-000", req["sha"])
			}
			w.WriteHeader(201)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/repos/testuser/") && strings.Contains(r.URL.Path, "/contents/"):
			callSequence = append(callSequence, "updateContents")
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/pulls"):
			callSequence = append(callSequence, "createPR")
			// Verify cross-repo head format.
			body, _ := io.ReadAll(r.Body)
			var req map[string]string
			json.Unmarshal(body, &req)
			if !strings.HasPrefix(req["head"], "testuser:") {
				t.Errorf("PR head = %q, want prefix 'testuser:'", req["head"])
			}
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(PRResult{Number: 42, HTMLURL: "https://github.com/test/pr/42"})

		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	c := newTestClientWithUser(srv, "tok", "testuser")
	pr, err := c.CreateRegistryPR(context.Background(), content, "Update registry")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pr.Number != 42 {
		t.Errorf("PR number = %d, want 42", pr.Number)
	}
	if pr.HTMLURL != "https://github.com/test/pr/42" {
		t.Errorf("PR URL = %q, want https://github.com/test/pr/42", pr.HTMLURL)
	}

	expected := []string{"forkRepo", "waitForFork", "syncFork", "getRef", "createRef", "getContents", "updateContents", "createPR"}
	if len(callSequence) != len(expected) {
		t.Fatalf("call sequence = %v, want %v", callSequence, expected)
	}
	for i, want := range expected {
		if callSequence[i] != want {
			t.Errorf("call[%d] = %q, want %q", i, callSequence[i], want)
		}
	}

	// Verify c.Owner is unchanged after the fork flow.
	if c.Owner != DefaultOwner {
		t.Errorf("Owner after fork flow = %q, want %q", c.Owner, DefaultOwner)
	}
}

func TestCreateRegistryPR_EmptyContent(t *testing.T) {
	apiCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCalled = true
		w.WriteHeader(500)
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	_, err := c.CreateRegistryPR(context.Background(), nil, "title")
	if err == nil {
		t.Fatal("expected error for empty content")
	}
	if !strings.Contains(err.Error(), "no registry content") {
		t.Errorf("error = %q, want to contain 'no registry content'", err.Error())
	}
	if apiCalled {
		t.Error("API was called despite empty content")
	}
}

func TestCreateRegistryPR_BranchCollision422(t *testing.T) {
	var createRefCount int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/forks"):
			w.WriteHeader(202)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/repos/testuser/") && !strings.Contains(r.URL.Path, "/git/") && !strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/merge-upstream"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/git/refs/heads/main"):
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]any{
				"ref":    "refs/heads/main",
				"object": map[string]string{"sha": "sha1"},
			})

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/refs"):
			createRefCount++
			if createRefCount == 1 {
				w.WriteHeader(422)
				w.Write([]byte(`{"message": "Reference already exists"}`))
				return
			}
			w.WriteHeader(201)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]string{"sha": "fsHA"})

		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/pulls"):
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(PRResult{Number: 1})

		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	c := newTestClientWithUser(srv, "tok", "testuser")
	_, err := c.CreateRegistryPR(context.Background(), []byte("content"), "title")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if createRefCount != 2 {
		t.Errorf("createRef called %d times, want 2", createRefCount)
	}
}

func TestCreateRegistryPR_BranchCollision422_Exhausted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/forks"):
			w.WriteHeader(202)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/repos/testuser/") && !strings.Contains(r.URL.Path, "/git/") && !strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/merge-upstream"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/git/refs/heads/main"):
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]any{
				"ref":    "refs/heads/main",
				"object": map[string]string{"sha": "sha1"},
			})

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/refs"):
			w.WriteHeader(422)
			w.Write([]byte(`{"message": "Reference already exists"}`))

		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	c := newTestClientWithUser(srv, "tok", "testuser")
	_, err := c.CreateRegistryPR(context.Background(), []byte("content"), "title")
	if err == nil {
		t.Fatal("expected error after exhausted retries")
	}
	if !strings.Contains(err.Error(), "collision") {
		t.Errorf("error = %q, want to contain 'collision'", err.Error())
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("%d", maxBranchRetries)) {
		t.Errorf("error = %q, want to contain retry count", err.Error())
	}
}

func TestCreateRegistryPR_StaleFileSHA409(t *testing.T) {
	var updateCount int
	var getContentsCount int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/forks"):
			w.WriteHeader(202)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/repos/testuser/") && !strings.Contains(r.URL.Path, "/git/") && !strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/merge-upstream"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/git/refs/heads/main"):
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]any{
				"ref":    "refs/heads/main",
				"object": map[string]string{"sha": "sha1"},
			})

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/refs"):
			w.WriteHeader(201)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/contents/"):
			getContentsCount++
			sha := "old-sha"
			if getContentsCount > 1 {
				sha = "new-sha"
			}
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]string{"sha": sha})

		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/contents/"):
			updateCount++
			if updateCount == 1 {
				w.WriteHeader(409)
				w.Write([]byte(`{"message": "Conflict"}`))
				return
			}
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/pulls"):
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(PRResult{Number: 7})

		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	c := newTestClientWithUser(srv, "tok", "testuser")
	pr, err := c.CreateRegistryPR(context.Background(), []byte("content"), "title")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pr.Number != 7 {
		t.Errorf("PR number = %d, want 7", pr.Number)
	}
	if updateCount != 2 {
		t.Errorf("updateContents called %d times, want 2", updateCount)
	}
	// getContents called once initially + once for retry
	if getContentsCount != 2 {
		t.Errorf("getContents called %d times, want 2", getContentsCount)
	}
}

func TestCreateRegistryPR_StaleFileSHA409_RetryExhausted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/forks"):
			w.WriteHeader(202)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/repos/testuser/") && !strings.Contains(r.URL.Path, "/git/") && !strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/merge-upstream"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/git/refs/heads/main"):
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]any{
				"ref":    "refs/heads/main",
				"object": map[string]string{"sha": "sha1"},
			})

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/refs"):
			w.WriteHeader(201)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]string{"sha": "stale-sha"})

		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(409)
			w.Write([]byte(`{"message": "Conflict"}`))

		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/git/refs/"):
			w.WriteHeader(204)

		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	c := newTestClientWithUser(srv, "tok", "testuser")
	_, err := c.CreateRegistryPR(context.Background(), []byte("content"), "title")
	if err == nil {
		t.Fatal("expected error after 409 retry exhausted")
	}
	if !strings.Contains(err.Error(), "updating file") {
		t.Errorf("error = %q, want to contain 'updating file'", err.Error())
	}
}

func TestCreateRegistryPR_CleanupOnFailure(t *testing.T) {
	var deleteRefCalled atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/forks"):
			w.WriteHeader(202)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/repos/testuser/") && !strings.Contains(r.URL.Path, "/git/") && !strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/merge-upstream"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/git/refs/heads/main"):
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]any{
				"ref":    "refs/heads/main",
				"object": map[string]string{"sha": "sha1"},
			})

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/refs"):
			w.WriteHeader(201)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]string{"sha": "fsha"})

		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/pulls"):
			w.WriteHeader(500)
			w.Write([]byte(`{"message": "Internal Server Error"}`))

		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/git/refs/"):
			deleteRefCalled.Store(true)
			w.WriteHeader(204)

		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	c := newTestClientWithUser(srv, "tok", "testuser")
	_, err := c.CreateRegistryPR(context.Background(), []byte("content"), "title")
	if err == nil {
		t.Fatal("expected error from createPR failure")
	}
	if !deleteRefCalled.Load() {
		t.Error("deleteRef was not called for cleanup")
	}
}

func TestCreateRegistryPR_CleanupOnUpdateFailure(t *testing.T) {
	var deleteRefCalled atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/forks"):
			w.WriteHeader(202)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/repos/testuser/") && !strings.Contains(r.URL.Path, "/git/") && !strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/merge-upstream"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/git/refs/heads/main"):
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]any{
				"ref":    "refs/heads/main",
				"object": map[string]string{"sha": "sha1"},
			})

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/refs"):
			w.WriteHeader(201)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]string{"sha": "fsha"})

		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/contents/"):
			// Non-409 error — no retry.
			w.WriteHeader(500)
			w.Write([]byte(`{"message": "Internal Server Error"}`))

		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/git/refs/"):
			deleteRefCalled.Store(true)
			w.WriteHeader(204)

		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	c := newTestClientWithUser(srv, "tok", "testuser")
	_, err := c.CreateRegistryPR(context.Background(), []byte("content"), "title")
	if err == nil {
		t.Fatal("expected error from updateContents failure")
	}
	if !deleteRefCalled.Load() {
		t.Error("deleteRef was not called for cleanup")
	}
}

func TestCreateRegistryPR_CleanupFailsGracefully(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/forks"):
			w.WriteHeader(202)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/repos/testuser/") && !strings.Contains(r.URL.Path, "/git/") && !strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/merge-upstream"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/git/refs/heads/main"):
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]any{
				"ref":    "refs/heads/main",
				"object": map[string]string{"sha": "sha1"},
			})

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/refs"):
			w.WriteHeader(201)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]string{"sha": "fsha"})

		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/pulls"):
			// createPR fails
			w.WriteHeader(502)
			w.Write([]byte(`{"message": "Bad Gateway"}`))

		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/git/refs/"):
			// deleteRef also fails
			w.WriteHeader(500)
			w.Write([]byte(`{"message": "Server Error"}`))

		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	c := newTestClientWithUser(srv, "tok", "testuser")
	_, err := c.CreateRegistryPR(context.Background(), []byte("content"), "title")
	if err == nil {
		t.Fatal("expected error")
	}
	// The returned error should be from createPR (502), not deleteRef (500).
	if !strings.Contains(err.Error(), "creating pull request") {
		t.Errorf("error = %q, want to contain 'creating pull request' (not deleteRef error)", err.Error())
	}
	var ae *APIError
	if !isAPIError(err, 502, &ae) {
		// The 502 should be wrapped inside.
		if !strings.Contains(err.Error(), "502") {
			t.Errorf("error = %q, want to reference status 502", err.Error())
		}
	}
}

func TestCreateRegistryPR_RateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/forks"):
			w.WriteHeader(202)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/repos/testuser/") && !strings.Contains(r.URL.Path, "/git/") && !strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/merge-upstream"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/git/refs/heads/main"):
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]any{
				"ref":    "refs/heads/main",
				"object": map[string]string{"sha": "sha1"},
			})

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/refs"):
			w.WriteHeader(201)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/contents/"):
			// Rate limited during getContents.
			w.WriteHeader(429)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/git/refs/"):
			w.WriteHeader(204)

		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	c := newTestClientWithUser(srv, "tok", "testuser")
	_, err := c.CreateRegistryPR(context.Background(), []byte("content"), "title")
	if err == nil {
		t.Fatal("expected error for rate limit")
	}
	if !IsRateLimited(unwrapAll(err)) {
		// The error is wrapped, so check string.
		if !strings.Contains(err.Error(), "rate limit exceeded") {
			t.Errorf("error = %q, want to mention rate limit", err.Error())
		}
	}
}

func TestCreateRegistryPR_Base64RoundTrip(t *testing.T) {
	reg := core.Registry{
		Keys: []core.KeyEntry{{
			Authority: "Test Authority",
			From:      "2025-01-01",
			To:        nil,
			Algorithm: "Ed25519",
			PublicKey:  "/PjT+j342wWZypb0m/4MSBsFhHrrqzpoTe2rZ9hf0XU=",
			Note:      "Test key",
		}},
	}
	content, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		t.Fatalf("json.MarshalIndent: %v", err)
	}
	content = append(content, '\n')

	var receivedContent []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/forks"):
			w.WriteHeader(202)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/repos/testuser/") && !strings.Contains(r.URL.Path, "/git/") && !strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/merge-upstream"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/git/refs/heads/main"):
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]any{
				"ref":    "refs/heads/main",
				"object": map[string]string{"sha": "sha1"},
			})

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/refs"):
			w.WriteHeader(201)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]string{"sha": "fsha"})

		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/contents/"):
			body, _ := io.ReadAll(r.Body)
			var req map[string]string
			json.Unmarshal(body, &req)
			decoded, decErr := base64.StdEncoding.DecodeString(req["content"])
			if decErr != nil {
				t.Errorf("base64 decode failed: %v", decErr)
			}
			receivedContent = decoded
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/pulls"):
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(PRResult{Number: 1})

		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	c := newTestClientWithUser(srv, "tok", "testuser")
	_, err = c.CreateRegistryPR(context.Background(), content, "title")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the received content is valid registry JSON.
	roundTripped, err := core.ValidateRegistry(receivedContent)
	if err != nil {
		t.Fatalf("received content is not valid registry: %v", err)
	}
	if len(roundTripped.Keys) != 1 {
		t.Errorf("round-tripped registry has %d keys, want 1", len(roundTripped.Keys))
	}
	if roundTripped.Keys[0].Authority != "Test Authority" {
		t.Errorf("authority = %q, want %q", roundTripped.Keys[0].Authority, "Test Authority")
	}
}

func TestCreateRegistryPR_422RetryAnyMessage(t *testing.T) {
	// Any 422 on ref creation triggers retry (not just "Reference already exists").
	var refAttempts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/forks"):
			w.WriteHeader(202)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/repos/testuser/") && !strings.Contains(r.URL.Path, "/git/") && !strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/merge-upstream"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/git/refs/heads/main"):
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]any{
				"ref":    "refs/heads/main",
				"object": map[string]string{"sha": "sha1"},
			})

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/refs"):
			refAttempts++
			// 422 with a non-standard message — should still retry.
			w.WriteHeader(422)
			w.Write([]byte(`{"message": "Validation Failed"}`))

		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	c := newTestClientWithUser(srv, "tok", "testuser")
	_, err := c.CreateRegistryPR(context.Background(), []byte("content"), "title")
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if !strings.Contains(err.Error(), "branch name collision") {
		t.Errorf("error = %q, want to contain 'branch name collision'", err.Error())
	}
	if refAttempts < 2 {
		t.Errorf("expected multiple ref creation attempts, got %d", refAttempts)
	}
}

// --- CreateRevocationPR ---

func TestCreateRevocationPR_Success(t *testing.T) {
	var callSequence []string
	content := []byte(`{"revocations": []}`)
	fullHash := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	var capturedBranchRef string
	var capturedContentsPath string
	var capturedPRTitle string
	var capturedPRBody string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/forks"):
			callSequence = append(callSequence, "forkRepo")
			w.WriteHeader(202)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/repos/testuser/") && !strings.Contains(r.URL.Path, "/git/") && !strings.Contains(r.URL.Path, "/contents/"):
			callSequence = append(callSequence, "waitForFork")
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/merge-upstream"):
			callSequence = append(callSequence, "syncFork")
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/git/refs/heads/main"):
			callSequence = append(callSequence, "getRef")
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]any{
				"ref":    "refs/heads/main",
				"object": map[string]string{"sha": "main-sha-000"},
			})

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/refs"):
			callSequence = append(callSequence, "createRef")
			body, _ := io.ReadAll(r.Body)
			var req map[string]string
			json.Unmarshal(body, &req)
			capturedBranchRef = req["ref"]
			w.WriteHeader(201)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/contents/"):
			callSequence = append(callSequence, "getContents")
			capturedContentsPath = r.URL.Path
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]string{"sha": "file-sha-rev"})

		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/contents/"):
			callSequence = append(callSequence, "updateContents")
			if !strings.Contains(r.URL.Path, "revocations.json") {
				t.Errorf("PUT path = %s, want to contain revocations.json", r.URL.Path)
			}
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/pulls"):
			callSequence = append(callSequence, "createPR")
			body, _ := io.ReadAll(r.Body)
			var req map[string]string
			json.Unmarshal(body, &req)
			capturedPRTitle = req["title"]
			capturedPRBody = req["body"]
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(PRResult{Number: 99, HTMLURL: "https://github.com/test/pr/99"})

		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	c := newTestClientWithUser(srv, "tok", "testuser")
	pr, err := c.CreateRevocationPR(context.Background(), content, fullHash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pr.Number != 99 {
		t.Errorf("PR number = %d, want 99", pr.Number)
	}
	if pr.HTMLURL != "https://github.com/test/pr/99" {
		t.Errorf("PR URL = %q, want https://github.com/test/pr/99", pr.HTMLURL)
	}

	// Verify call sequence.
	expected := []string{"forkRepo", "waitForFork", "syncFork", "getRef", "createRef", "getContents", "updateContents", "createPR"}
	if len(callSequence) != len(expected) {
		t.Fatalf("call sequence = %v, want %v", callSequence, expected)
	}
	for i, want := range expected {
		if callSequence[i] != want {
			t.Errorf("call[%d] = %q, want %q", i, callSequence[i], want)
		}
	}

	// Verify branch name contains "revoke-" prefix.
	if !strings.Contains(capturedBranchRef, "revoke-") {
		t.Errorf("branch ref = %q, want to contain 'revoke-'", capturedBranchRef)
	}

	// Verify contents path targets revocations.json.
	if !strings.Contains(capturedContentsPath, "revocations.json") {
		t.Errorf("getContents path = %q, want to contain revocations.json", capturedContentsPath)
	}

	// Verify PR title contains "Revoke credential".
	shortHash := fullHash[:16]
	if !strings.Contains(capturedPRTitle, "Revoke credential") {
		t.Errorf("PR title = %q, want to contain 'Revoke credential'", capturedPRTitle)
	}
	if !strings.Contains(capturedPRTitle, shortHash) {
		t.Errorf("PR title = %q, want to contain short hash %q", capturedPRTitle, shortHash)
	}

	// Verify PR body contains the full hash.
	if !strings.Contains(capturedPRBody, fullHash) {
		t.Errorf("PR body = %q, want to contain full hash %q", capturedPRBody, fullHash)
	}
}

func TestCreateRevocationPR_EmptyContent(t *testing.T) {
	apiCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCalled = true
		w.WriteHeader(500)
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	_, err := c.CreateRevocationPR(context.Background(), nil, "somehash")
	if err == nil {
		t.Fatal("expected error for empty content")
	}
	if !strings.Contains(err.Error(), "no revocation content") {
		t.Errorf("error = %q, want to contain 'no revocation content'", err.Error())
	}
	if apiCalled {
		t.Error("API was called despite empty content")
	}

	// Also test with zero-length slice.
	_, err = c.CreateRevocationPR(context.Background(), []byte{}, "somehash")
	if err == nil {
		t.Fatal("expected error for zero-length content")
	}
	if !strings.Contains(err.Error(), "no revocation content") {
		t.Errorf("error = %q, want to contain 'no revocation content'", err.Error())
	}
}

func TestCreateRevocationPR_LongHash(t *testing.T) {
	longHash := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	content := []byte(`{"revocations": []}`)

	var capturedBranchRef string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/forks"):
			w.WriteHeader(202)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/repos/testuser/") && !strings.Contains(r.URL.Path, "/git/") && !strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/merge-upstream"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/git/refs/heads/main"):
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]any{
				"ref":    "refs/heads/main",
				"object": map[string]string{"sha": "sha1"},
			})

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/refs"):
			body, _ := io.ReadAll(r.Body)
			var req map[string]string
			json.Unmarshal(body, &req)
			capturedBranchRef = req["ref"]
			w.WriteHeader(201)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]string{"sha": "fsha"})

		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/pulls"):
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(PRResult{Number: 1})

		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	c := newTestClientWithUser(srv, "tok", "testuser")
	_, err := c.CreateRevocationPR(context.Background(), content, longHash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Branch ref should contain "revoke-" followed by exactly 16 hex chars, then "-".
	// The full 64-char hash must NOT appear in the branch name.
	expectedPrefix := "revoke-" + longHash[:16] + "-"
	if !strings.Contains(capturedBranchRef, expectedPrefix) {
		t.Errorf("branch ref = %q, want to contain %q", capturedBranchRef, expectedPrefix)
	}
	// Ensure the full hash is NOT in the branch name (it was truncated).
	if strings.Contains(capturedBranchRef, longHash) {
		t.Errorf("branch ref = %q, should not contain full hash %q", capturedBranchRef, longHash)
	}
}

func TestCreateRevocationPR_ShortHash(t *testing.T) {
	// Hash shorter than 16 chars should be used as-is (no truncation).
	shortHash := "abc123"
	content := []byte(`{"revocations": []}`)

	var capturedBranchRef string
	var capturedPRTitle string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/forks"):
			w.WriteHeader(202)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/repos/testuser/") && !strings.Contains(r.URL.Path, "/git/") && !strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/merge-upstream"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/git/refs/heads/main"):
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]any{
				"ref":    "refs/heads/main",
				"object": map[string]string{"sha": "sha1"},
			})

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/refs"):
			body, _ := io.ReadAll(r.Body)
			var req map[string]string
			json.Unmarshal(body, &req)
			capturedBranchRef = req["ref"]
			w.WriteHeader(201)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]string{"sha": "fsha"})

		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/pulls"):
			body, _ := io.ReadAll(r.Body)
			var req map[string]string
			json.Unmarshal(body, &req)
			capturedPRTitle = req["title"]
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(PRResult{Number: 1})

		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	c := newTestClientWithUser(srv, "tok", "testuser")
	_, err := c.CreateRevocationPR(context.Background(), content, shortHash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Short hash should appear in full in the branch prefix.
	expectedPrefix := "revoke-" + shortHash + "-"
	if !strings.Contains(capturedBranchRef, expectedPrefix) {
		t.Errorf("branch ref = %q, want to contain %q", capturedBranchRef, expectedPrefix)
	}

	// Title should use the short hash as-is.
	if !strings.Contains(capturedPRTitle, shortHash) {
		t.Errorf("PR title = %q, want to contain %q", capturedPRTitle, shortHash)
	}
}

// --- helpers ---

// newTestClient creates a Client pointing at the given test server.
func newTestClient(srv *httptest.Server, token string) *Client {
	c := NewClient(token)
	c.HTTPClient = srv.Client()
	// Override the base URL by using a custom doJSON — but since we can't
	// override apiBaseURL (const), we override Owner/Repo and route through
	// the test server via a custom transport.
	//
	// Simpler approach: replace the http client and rewrite URLs.
	origTransport := srv.Client().Transport
	c.HTTPClient.Transport = &rewriteTransport{
		base:      origTransport,
		targetURL: srv.URL,
	}
	return c
}

// newTestClientWithUser creates a Client with a username, pointing at the given test server.
func newTestClientWithUser(srv *httptest.Server, token, username string) *Client {
	c := newTestClient(srv, token)
	c.username = username
	return c
}

// rewriteTransport rewrites all request URLs to point at the test server.
type rewriteTransport struct {
	base      http.RoundTripper
	targetURL string
}

func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace https://api.github.com with the test server URL.
	req.URL.Scheme = "http"
	req.URL.Host = strings.TrimPrefix(t.targetURL, "http://")
	return t.base.RoundTrip(req)
}

// isAPIError checks if err (possibly wrapped) contains an *APIError with the given status.
func isAPIError(err error, status int, target **APIError) bool {
	var ae *APIError
	if errors.As(err, &ae) {
		*target = ae
		return ae.StatusCode == status
	}
	return false
}

// unwrapAll returns the innermost error in a chain.
func unwrapAll(err error) error {
	for {
		inner := errors.Unwrap(err)
		if inner == nil {
			return err
		}
		err = inner
	}
}

// --- H2: Redirect auth stripping tests ---

func TestDoJSON_RedirectStripsAuth(t *testing.T) {
	// Server B records whether it received an Authorization header.
	var gotAuth string
	srvB := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer srvB.Close()

	// Server A redirects to server B (cross-host).
	srvA := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srvB.URL+"/target", http.StatusFound)
	}))
	defer srvA.Close()

	// Build a transport that trusts both TLS test servers.
	transport := srvA.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.InsecureSkipVerify = true

	c := &Client{
		token: "secret-token",
		HTTPClient: &http.Client{
			CheckRedirect: safeCheckRedirect,
			Transport:     transport,
		},
		Owner: DefaultOwner,
		Repo:  DefaultRepo,
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srvA.URL+"/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret-token")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if gotAuth != "" {
		t.Errorf("server B received Authorization header %q, want empty (should be stripped)", gotAuth)
	}
}

func TestDoJSON_SameHostRedirectKeepsAuth(t *testing.T) {
	var gotAuth string
	var reqCount int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount++
		if reqCount == 1 {
			http.Redirect(w, r, "/redirected", http.StatusFound)
			return
		}
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := &Client{
		token: "keep-me",
		HTTPClient: &http.Client{
			CheckRedirect: safeCheckRedirect,
			Transport:     srv.Client().Transport,
		},
		Owner: DefaultOwner,
		Repo:  DefaultRepo,
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer keep-me")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if gotAuth != "Bearer keep-me" {
		t.Errorf("same-host redirect lost Authorization header: got %q, want %q", gotAuth, "Bearer keep-me")
	}
}

func TestSafeCheckRedirect_GitHubSubdomain(t *testing.T) {
	tests := []struct {
		name     string
		origHost string
		target   string
		wantAuth bool
	}{
		{"github.com keeps auth", "api.github.com", "https://github.com/path", true},
		{"uploads.github.com keeps auth", "api.github.com", "https://uploads.github.com/path", true},
		{"api.github.com keeps auth", "api.github.com", "https://api.github.com/path", true},
		{"evil.com strips auth", "api.github.com", "https://evil.com/path", false},
		{"notgithub.com strips auth", "api.github.com", "https://notgithub.com/path", false},
		{"evil.github.com.evil.com strips auth", "api.github.com", "https://evil.github.com.evil.com/path", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origURL, _ := url.Parse("https://" + tt.origHost + "/original")
			targetURL, _ := url.Parse(tt.target)

			origReq := &http.Request{URL: origURL, Header: http.Header{}}
			req := &http.Request{
				URL:    targetURL,
				Header: http.Header{"Authorization": {"Bearer tok"}},
			}

			err := safeCheckRedirect(req, []*http.Request{origReq})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			hasAuth := req.Header.Get("Authorization") != ""
			if hasAuth != tt.wantAuth {
				t.Errorf("Authorization present = %v, want %v", hasAuth, tt.wantAuth)
			}
		})
	}
}

func TestSafeCheckRedirect_RejectsHTTP(t *testing.T) {
	origURL, _ := url.Parse("https://api.github.com/original")
	targetURL, _ := url.Parse("http://api.github.com/path")

	origReq := &http.Request{URL: origURL, Header: http.Header{}}
	req := &http.Request{
		URL:    targetURL,
		Header: http.Header{"Authorization": {"Bearer tok"}},
	}

	err := safeCheckRedirect(req, []*http.Request{origReq})
	if err == nil {
		t.Fatal("expected error for HTTP redirect")
	}
	if !strings.Contains(err.Error(), "non-HTTPS") {
		t.Errorf("error should mention non-HTTPS, got: %v", err)
	}
}

// --- IsGitHubHost tests ---

func TestIsGitHubHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"github.com", true},
		{"api.github.com", true},
		{"uploads.github.com", true},
		{"github.com:443", true},
		{"api.github.com:443", true},
		{"evil.com", false},
		{"notgithub.com", false},
		{"github.com.evil.com", false},
		{"evil-github.com", false},
		{"", false},
		{"[::1]:443", false},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got := IsGitHubHost(tt.host)
			if got != tt.want {
				t.Errorf("IsGitHubHost(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

// sanitizeForLog tests moved to core/sanitize_test.go

// --- Finding #5: Client String/GoString redacts token ---

func TestClient_String_RedactsToken(t *testing.T) {
	secret := "ghp_SuperSecretToken12345"
	c := NewClient(secret)

	str := fmt.Sprintf("%v", c)
	if strings.Contains(str, secret) {
		t.Errorf("String() contains token: %s", str)
	}
	if !strings.Contains(str, "[REDACTED]") {
		t.Errorf("String() missing [REDACTED]: %s", str)
	}
	if !strings.Contains(str, DefaultOwner) {
		t.Errorf("String() missing Owner: %s", str)
	}
	if !strings.Contains(str, DefaultRepo) {
		t.Errorf("String() missing Repo: %s", str)
	}

	goStr := fmt.Sprintf("%#v", c)
	if strings.Contains(goStr, secret) {
		t.Errorf("GoString() contains token: %s", goStr)
	}
	if !strings.Contains(goStr, "[REDACTED]") {
		t.Errorf("GoString() missing [REDACTED]: %s", goStr)
	}
}

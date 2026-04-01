package ghapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var forkTestMu sync.Mutex

// withForkOverrides locks the fork test mutex, sets poll vars, and
// restores originals + unlocks via t.Cleanup. Tests using this helper
// MUST NOT call t.Parallel().
func withForkOverrides(t *testing.T, interval time.Duration, attempts int) {
	t.Helper()
	forkTestMu.Lock()
	origInterval := forkPollInterval
	origAttempts := forkMaxPollAttempts
	forkPollInterval = interval
	forkMaxPollAttempts = attempts
	t.Cleanup(func() {
		forkPollInterval = origInterval
		forkMaxPollAttempts = origAttempts
		forkTestMu.Unlock()
	})
}

// --- ForkError ---

func TestForkError_Error(t *testing.T) {
	fe := &ForkError{Phase: "create", Wrapped: fmt.Errorf("network timeout")}
	got := fe.Error()
	if got != "fork create failed: network timeout" {
		t.Errorf("ForkError.Error() = %q, want %q", got, "fork create failed: network timeout")
	}
}

func TestForkError_Unwrap(t *testing.T) {
	inner := fmt.Errorf("inner error")
	fe := &ForkError{Phase: "poll", Wrapped: inner}
	if fe.Unwrap() != inner {
		t.Error("ForkError.Unwrap() did not return the wrapped error")
	}
}

func TestIsForkError(t *testing.T) {
	fe := &ForkError{Phase: "create", Wrapped: fmt.Errorf("test")}
	if !IsForkError(fe) {
		t.Error("IsForkError returned false for *ForkError")
	}

	wrapped := fmt.Errorf("outer: %w", fe)
	if !IsForkError(wrapped) {
		t.Error("IsForkError returned false for wrapped *ForkError")
	}

	if IsForkError(fmt.Errorf("plain error")) {
		t.Error("IsForkError returned true for non-ForkError")
	}

	if IsForkError(nil) {
		t.Error("IsForkError returned true for nil")
	}
}

// --- NewClientWithUser ---

func TestNewClientWithUser(t *testing.T) {
	c := NewClientWithUser("tok_abc", "myuser")
	if c.token != "tok_abc" {
		t.Errorf("Token = %q, want %q", c.token, "tok_abc")
	}
	if c.username != "myuser" {
		t.Errorf("username = %q, want %q", c.username, "myuser")
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
}

// --- forkRepo ---

func TestForkRepo_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/forks") {
			t.Errorf("path = %s, want suffix /forks", r.URL.Path)
		}
		w.WriteHeader(202)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	err := c.forkRepo(context.Background(), "owner", "repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestForkRepo_ExistingFork200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	err := c.forkRepo(context.Background(), "owner", "repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestForkRepo_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte(`{"message": "Forbidden"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	err := c.forkRepo(context.Background(), "owner", "repo")
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsForbidden(err) {
		t.Errorf("expected 403, got %v", err)
	}
}

// --- waitForFork ---

func TestWaitForFork_ImmediateSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	err := c.waitForFork(context.Background(), "user", "repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWaitForFork_SuccessAfterPolls(t *testing.T) {
	// Speed up poll interval for testing.
	withForkOverrides(t, 1*time.Millisecond, forkMaxPollAttempts)

	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n < 3 {
			w.WriteHeader(404)
			w.Write([]byte(`{"message": "Not Found"}`))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	err := c.waitForFork(context.Background(), "user", "repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if atomic.LoadInt32(&attempts) != 3 {
		t.Errorf("attempts = %d, want 3", atomic.LoadInt32(&attempts))
	}
}

func TestWaitForFork_ExhaustedAttempts(t *testing.T) {
	withForkOverrides(t, 1*time.Millisecond, 3)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte(`{"message": "Not Found"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	err := c.waitForFork(context.Background(), "user", "repo")
	if err == nil {
		t.Fatal("expected error after exhausted attempts")
	}
	if !IsForkError(err) {
		t.Errorf("expected ForkError, got %T: %v", err, err)
	}
	var fe *ForkError
	if errors.As(err, &fe) {
		if fe.Phase != "poll" {
			t.Errorf("ForkError.Phase = %q, want %q", fe.Phase, "poll")
		}
	}
	if !strings.Contains(err.Error(), "not ready after") {
		t.Errorf("error = %q, want to contain 'not ready after'", err.Error())
	}
}

func TestWaitForFork_Non404FailsFast(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte(`{"message": "Internal Server Error"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	err := c.waitForFork(context.Background(), "user", "repo")
	if err == nil {
		t.Fatal("expected error for 500")
	}
	if !IsForkError(err) {
		t.Errorf("expected ForkError, got %T: %v", err, err)
	}
	var fe *ForkError
	if errors.As(err, &fe) {
		if fe.Phase != "poll" {
			t.Errorf("ForkError.Phase = %q, want %q", fe.Phase, "poll")
		}
	}
}

func TestWaitForFork_ContextCancelled(t *testing.T) {
	withForkOverrides(t, 10*time.Second, forkMaxPollAttempts) // Long interval so cancel fires first.

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte(`{"message": "Not Found"}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel after a short delay.
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	c := newTestClient(srv, "tok")
	err := c.waitForFork(ctx, "user", "repo")
	if err == nil {
		t.Fatal("expected error after context cancellation")
	}
	if !IsForkError(err) {
		t.Errorf("expected ForkError, got %T: %v", err, err)
	}
	var fe *ForkError
	if errors.As(err, &fe) {
		if fe.Phase != "poll" {
			t.Errorf("ForkError.Phase = %q, want %q", fe.Phase, "poll")
		}
	}
}

// --- syncFork ---

func TestSyncFork_Success(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/merge-upstream") {
			t.Errorf("path = %s, want suffix /merge-upstream", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		var req map[string]string
		json.Unmarshal(body, &req)
		if req["branch"] != "main" {
			t.Errorf("branch = %q, want %q", req["branch"], "main")
		}
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	c.syncFork(context.Background(), "user", "repo")
	if !called {
		t.Error("syncFork did not make a request")
	}
}

func TestSyncFork_422AlreadyUpToDate(t *testing.T) {
	// 422 is silently swallowed (already up to date).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(422)
		w.Write([]byte(`{"message": "merge-upstream is not possible"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	// Should not panic or log an error — just return.
	c.syncFork(context.Background(), "user", "repo")
}

func TestSyncFork_OtherError(t *testing.T) {
	// Non-422 errors are logged and swallowed — no return value.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte(`{"message": "Internal Server Error"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	// Should not panic — just logs a warning.
	c.syncFork(context.Background(), "user", "repo")
}

// --- createForkFilePR ---

func TestCreateForkFilePR_ForkRepoFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte(`{"message": "Forbidden"}`))
	}))
	defer srv.Close()

	c := newTestClientWithUser(srv, "tok", "testuser")
	_, err := c.createForkFilePR(context.Background(), "path.json", []byte("data"), "prefix-", "title", "body")
	if err == nil {
		t.Fatal("expected error when forkRepo fails")
	}
	if !IsForkError(err) {
		t.Errorf("expected ForkError, got %T: %v", err, err)
	}
	var fe *ForkError
	if errors.As(err, &fe) {
		if fe.Phase != "create" {
			t.Errorf("ForkError.Phase = %q, want %q", fe.Phase, "create")
		}
	}
}

func TestCreateForkFilePR_WaitForForkFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/forks"):
			w.WriteHeader(202)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/repos/testuser/"):
			// Non-404 error to fail fast.
			w.WriteHeader(500)
			w.Write([]byte(`{"message": "Internal Server Error"}`))

		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	c := newTestClientWithUser(srv, "tok", "testuser")
	_, err := c.createForkFilePR(context.Background(), "path.json", []byte("data"), "prefix-", "title", "body")
	if err == nil {
		t.Fatal("expected error when waitForFork fails")
	}
	if !IsForkError(err) {
		t.Errorf("expected ForkError, got %T: %v", err, err)
	}
}

func TestCreateForkFilePR_GetForkMainRefFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/forks"):
			w.WriteHeader(202)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/repos/testuser/") && !strings.Contains(r.URL.Path, "/git/"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/merge-upstream"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/git/refs/heads/main"):
			w.WriteHeader(404)
			w.Write([]byte(`{"message": "Not Found"}`))

		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	c := newTestClientWithUser(srv, "tok", "testuser")
	_, err := c.createForkFilePR(context.Background(), "path.json", []byte("data"), "prefix-", "title", "body")
	if err == nil {
		t.Fatal("expected error when getRefFor fails")
	}
	if !strings.Contains(err.Error(), "getting fork main ref") {
		t.Errorf("error = %q, want to contain 'getting fork main ref'", err.Error())
	}
}

func TestCreateForkFilePR_GetFileSHAFails_Cleanup(t *testing.T) {
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
	_, err := c.createForkFilePR(context.Background(), "path.json", []byte("data"), "prefix-", "title", "body")
	if err == nil {
		t.Fatal("expected error when getContentsFor fails")
	}
	if !strings.Contains(err.Error(), "getting file SHA from fork") {
		t.Errorf("error = %q, want to contain 'getting file SHA from fork'", err.Error())
	}
	// Wait briefly for cleanup goroutine.
	time.Sleep(50 * time.Millisecond)
	if !deleteRefCalled.Load() {
		t.Error("cleanup deleteRef was not called")
	}
}

func TestCreateForkFilePR_UpdateContentsFails_Cleanup(t *testing.T) {
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
			// Non-409 error.
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
	_, err := c.createForkFilePR(context.Background(), "path.json", []byte("data"), "prefix-", "title", "body")
	if err == nil {
		t.Fatal("expected error when updateContents fails")
	}
	time.Sleep(50 * time.Millisecond)
	if !deleteRefCalled.Load() {
		t.Error("cleanup deleteRef was not called")
	}
}

func TestCreateForkFilePR_CreatePRFails_Cleanup(t *testing.T) {
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
	_, err := c.createForkFilePR(context.Background(), "path.json", []byte("data"), "prefix-", "title", "body")
	if err == nil {
		t.Fatal("expected error when createPR fails")
	}
	if !strings.Contains(err.Error(), "creating pull request") {
		t.Errorf("error = %q, want to contain 'creating pull request'", err.Error())
	}
	time.Sleep(50 * time.Millisecond)
	if !deleteRefCalled.Load() {
		t.Error("cleanup deleteRef was not called")
	}
}

func TestCreateForkFilePR_CrossRepoHead(t *testing.T) {
	// Verify the PR head is in "username:branch" format.
	var capturedHead string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/forks"):
			w.WriteHeader(202)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/repos/forkuser/") && !strings.Contains(r.URL.Path, "/git/") && !strings.Contains(r.URL.Path, "/contents/"):
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
			body, _ := io.ReadAll(r.Body)
			var req map[string]string
			json.Unmarshal(body, &req)
			capturedHead = req["head"]
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(PRResult{Number: 1})

		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	c := newTestClientWithUser(srv, "tok", "forkuser")
	_, err := c.createForkFilePR(context.Background(), "path.json", []byte("data"), "prefix-", "title", "body")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(capturedHead, "forkuser:") {
		t.Errorf("PR head = %q, want prefix 'forkuser:'", capturedHead)
	}
}

// --- Username guard ---

func TestCreateRegistryPR_NoUsername(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("API should not be called when username is empty")
		w.WriteHeader(500)
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok") // No username set.
	_, err := c.CreateRegistryPR(context.Background(), []byte("content"), "title")
	if err == nil {
		t.Fatal("expected error for missing username")
	}
	if !strings.Contains(err.Error(), "username not set") {
		t.Errorf("error = %q, want to contain 'username not set'", err.Error())
	}
}

func TestCreateRevocationPR_NoUsername(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("API should not be called when username is empty")
		w.WriteHeader(500)
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok") // No username set.
	_, err := c.CreateRevocationPR(context.Background(), []byte("content"), "somehash")
	if err == nil {
		t.Fatal("expected error for missing username")
	}
	if !strings.Contains(err.Error(), "username not set") {
		t.Errorf("error = %q, want to contain 'username not set'", err.Error())
	}
}

// --- *For delegation methods ---

func TestGetRefFor_UsesExplicitOwnerRepo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/repos/customowner/customrepo/") {
			t.Errorf("path = %s, want to contain /repos/customowner/customrepo/", r.URL.Path)
		}
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]any{
			"ref":    "refs/heads/main",
			"object": map[string]string{"sha": "abc123"},
		})
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	sha, err := c.getRefFor(context.Background(), "customowner", "customrepo", "heads/main")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sha != "abc123" {
		t.Errorf("SHA = %q, want %q", sha, "abc123")
	}
}

func TestCreateRefFor_UsesExplicitOwnerRepo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/repos/customowner/customrepo/") {
			t.Errorf("path = %s, want to contain /repos/customowner/customrepo/", r.URL.Path)
		}
		w.WriteHeader(201)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	err := c.createRefFor(context.Background(), "customowner", "customrepo", "heads/test", "sha123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteRefExplicit_UsesExplicitOwnerRepo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s, want DELETE", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/repos/customowner/customrepo/") {
			t.Errorf("path = %s, want to contain /repos/customowner/customrepo/", r.URL.Path)
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	err := c.deleteRefExplicit(context.Background(), "customowner", "customrepo", "heads/test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetContentsFor_UsesExplicitOwnerRepo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/repos/customowner/customrepo/") {
			t.Errorf("path = %s, want to contain /repos/customowner/customrepo/", r.URL.Path)
		}
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]string{"sha": "filesha123"})
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	sha, err := c.getContentsFor(context.Background(), "customowner", "customrepo", "path/file.json", "main")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sha != "filesha123" {
		t.Errorf("SHA = %q, want %q", sha, "filesha123")
	}
}

func TestUpdateContentsFor_UsesExplicitOwnerRepo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/repos/customowner/customrepo/") {
			t.Errorf("path = %s, want to contain /repos/customowner/customrepo/", r.URL.Path)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	err := c.updateContentsFor(context.Background(), "customowner", "customrepo", "path/file.json", "branch", []byte("data"), "sha", "msg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCreatePRFor_UsesExplicitOwnerRepo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/repos/customowner/customrepo/") {
			t.Errorf("path = %s, want to contain /repos/customowner/customrepo/", r.URL.Path)
		}
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(PRResult{Number: 10, HTMLURL: "https://example.com/pr/10"})
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	pr, err := c.createPRFor(context.Background(), "customowner", "customrepo", "user:branch", "main", "title", "body")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pr.Number != 10 {
		t.Errorf("PR number = %d, want 10", pr.Number)
	}
}

func TestCreateBranchWithRetryFor_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/repos/customowner/customrepo/") {
			t.Errorf("path = %s, want to contain /repos/customowner/customrepo/", r.URL.Path)
		}
		w.WriteHeader(201)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	name, err := c.createBranchWithRetryFor(context.Background(), "customowner", "customrepo", "sha1", "prefix-")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(name, "prefix-") {
		t.Errorf("branch name = %q, want prefix 'prefix-'", name)
	}
}

func TestUpdateContentsWithRetryFor_409Retry(t *testing.T) {
	var updateCount int
	var getContentsCount int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut:
			updateCount++
			if updateCount == 1 {
				w.WriteHeader(409)
				w.Write([]byte(`{"message": "Conflict"}`))
				return
			}
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/contents/"):
			getContentsCount++
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]string{"sha": "newsha"})

		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	err := c.updateContentsWithRetryFor(context.Background(), "owner", "repo", "file.json", "branch", []byte("data"), "oldsha", "msg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updateCount != 2 {
		t.Errorf("update attempts = %d, want 2", updateCount)
	}
	if getContentsCount != 1 {
		t.Errorf("getContents calls = %d, want 1", getContentsCount)
	}
}

func TestUpdateContentsWithRetryFor_Non409Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte(`{"message": "Internal Server Error"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	err := c.updateContentsWithRetryFor(context.Background(), "owner", "repo", "file.json", "branch", []byte("data"), "sha", "msg")
	if err == nil {
		t.Fatal("expected error for 500")
	}
	if !strings.Contains(err.Error(), "updating file") {
		t.Errorf("error = %q, want to contain 'updating file'", err.Error())
	}
}

func TestUpdateContentsWithRetryFor_409RefetchFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut:
			w.WriteHeader(409)
			w.Write([]byte(`{"message": "Conflict"}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(500)
			w.Write([]byte(`{"message": "Internal Server Error"}`))

		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	err := c.updateContentsWithRetryFor(context.Background(), "owner", "repo", "file.json", "branch", []byte("data"), "sha", "msg")
	if err == nil {
		t.Fatal("expected error when refetch fails")
	}
	if !strings.Contains(err.Error(), "re-fetching file SHA") {
		t.Errorf("error = %q, want to contain 're-fetching file SHA'", err.Error())
	}
}

func TestUpdateContentsWithRetryFor_409RetryAlsoFails(t *testing.T) {
	var putCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut:
			putCount++
			w.WriteHeader(409)
			w.Write([]byte(`{"message": "Conflict"}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]string{"sha": "newsha"})

		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	err := c.updateContentsWithRetryFor(context.Background(), "owner", "repo", "file.json", "branch", []byte("data"), "sha", "msg")
	if err == nil {
		t.Fatal("expected error when retry also fails")
	}
	if !strings.Contains(err.Error(), "updating file (retry)") {
		t.Errorf("error = %q, want to contain 'updating file (retry)'", err.Error())
	}
	if putCount != 2 {
		t.Errorf("PUT calls = %d, want 2", putCount)
	}
}

// --- forkPollInterval var tests ---

func TestForkPollVars_Defaults(t *testing.T) {
	if forkPollInterval != 3*time.Second {
		t.Errorf("forkPollInterval = %v, want 3s", forkPollInterval)
	}
	if forkMaxPollAttempts != 15 {
		t.Errorf("forkMaxPollAttempts = %d, want 15", forkMaxPollAttempts)
	}
}

// --- Delegation wrappers call *For with default owner/repo ---

func TestGetRef_DelegatesToGetRefFor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify it uses the client's default Owner/Repo.
		if !strings.Contains(r.URL.Path, "/repos/"+DefaultOwner+"/"+DefaultRepo+"/") {
			t.Errorf("path = %s, want to contain default owner/repo", r.URL.Path)
		}
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]any{
			"ref":    "refs/heads/main",
			"object": map[string]string{"sha": "delegated-sha"},
		})
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	sha, err := c.getRef(context.Background(), "heads/main")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sha != "delegated-sha" {
		t.Errorf("SHA = %q, want %q", sha, "delegated-sha")
	}
}

func TestDeleteRef_DelegatesToDeleteRefExplicit(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s, want DELETE", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/repos/"+DefaultOwner+"/"+DefaultRepo+"/") {
			t.Errorf("path = %s, want to contain default owner/repo", r.URL.Path)
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	err := c.deleteRef(context.Background(), "heads/test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("deleteRef did not make a request")
	}
}

// --- Cleanup failure on fork branch is graceful ---

func TestCreateForkFilePR_CleanupFailsGracefully(t *testing.T) {
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
			w.WriteHeader(502)
			w.Write([]byte(`{"message": "Bad Gateway"}`))

		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/git/refs/"):
			// Cleanup also fails.
			w.WriteHeader(500)
			w.Write([]byte(`{"message": "Server Error"}`))

		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	c := newTestClientWithUser(srv, "tok", "testuser")
	_, err := c.createForkFilePR(context.Background(), "path.json", []byte("data"), "prefix-", "title", "body")
	if err == nil {
		t.Fatal("expected error")
	}
	// Error should be from createPR, not cleanup.
	if !strings.Contains(err.Error(), "creating pull request") {
		t.Errorf("error = %q, want to contain 'creating pull request'", err.Error())
	}
}

// --- PR targets upstream, not fork ---

func TestCreateForkFilePR_PRTargetsUpstream(t *testing.T) {
	var prPath string

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
			prPath = r.URL.Path
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(PRResult{Number: 1})

		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	c := newTestClientWithUser(srv, "tok", "testuser")
	_, err := c.createForkFilePR(context.Background(), "path.json", []byte("data"), "prefix-", "title", "body")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// PR should be created on upstream (c.Owner), not on fork (testuser).
	if !strings.Contains(prPath, "/repos/"+DefaultOwner+"/"+DefaultRepo+"/") {
		t.Errorf("PR path = %s, want to contain upstream owner/repo", prPath)
	}
	if strings.Contains(prPath, "/repos/testuser/") {
		t.Errorf("PR path = %s, should not target the fork", prPath)
	}
}

// --- Batch 2 gap-fill tests ---

func TestCreateRegistryPR_ForkSyncFailsNonFatal(t *testing.T) {
	// End-to-end: syncFork returns 500, but PR still succeeds.
	// Also verify warning is logged.
	withForkOverrides(t, 0, 1)

	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(nil) })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/forks"):
			w.WriteHeader(202)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/repos/testuser/") && !strings.Contains(r.URL.Path, "/git/") && !strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/merge-upstream"):
			w.WriteHeader(500)
			w.Write([]byte(`{"message":"internal error"}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/git/refs/heads/main"):
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]any{
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
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(PRResult{Number: 1})

		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	c := newTestClientWithUser(srv, "tok", "testuser")
	pr, err := c.CreateRegistryPR(context.Background(), []byte("content"), "title")
	if err != nil {
		t.Fatalf("expected PR to succeed despite sync failure, got: %v", err)
	}
	if pr.Number != 1 {
		t.Errorf("PR number = %d, want 1", pr.Number)
	}

	if !strings.Contains(buf.String(), "syncFork") {
		t.Errorf("expected sync warning in log, got: %q", buf.String())
	}
}

func TestCreateRegistryPR_UpdateContents409Retry(t *testing.T) {
	// End-to-end: first PUT returns 409, retry re-fetches from fork with branch ref, second PUT succeeds.
	withForkOverrides(t, 0, 1)

	var putCount int
	var retryGetRef string
	var retryGetOwner string
	var secondPutOwner string

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
				"object": map[string]string{"sha": "sha1"},
			})

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/refs"):
			w.WriteHeader(201)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/contents/"):
			// Track the retry re-fetch: second GET /contents is the 409 retry.
			if putCount > 0 {
				retryGetRef = r.URL.Query().Get("ref")
				// Extract owner from path: /repos/{owner}/...
				parts := strings.Split(r.URL.Path, "/")
				if len(parts) >= 3 {
					retryGetOwner = parts[2]
				}
			}
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]string{"sha": "new-sha"})

		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/contents/"):
			putCount++
			if putCount == 1 {
				// First PUT → 409.
				w.WriteHeader(409)
				w.Write([]byte(`{"message":"sha does not match"}`))
				return
			}
			// Second PUT — capture owner from path.
			parts := strings.Split(r.URL.Path, "/")
			if len(parts) >= 3 {
				secondPutOwner = parts[2]
			}
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

	if putCount != 2 {
		t.Errorf("PUT count = %d, want 2", putCount)
	}

	// Verify retry re-fetch targeted the fork owner (not upstream).
	if retryGetOwner != "testuser" {
		t.Errorf("retry GET /contents owner = %q, want %q", retryGetOwner, "testuser")
	}

	// Verify retry re-fetch used the branch ref (not "main").
	if retryGetRef == "main" || retryGetRef == "" {
		t.Errorf("retry GET /contents ref = %q, want branch name (not 'main')", retryGetRef)
	}

	// Verify second PUT also targeted the fork owner.
	if secondPutOwner != "testuser" {
		t.Errorf("second PUT owner = %q, want %q", secondPutOwner, "testuser")
	}
}

func TestForkTestUsername_DistinctFromDefaultOwner(t *testing.T) {
	// Guard: the test username must differ from DefaultOwner to prevent routing ambiguity.
	testUsername := "testuser"
	if testUsername == DefaultOwner {
		t.Fatalf("test username %q must differ from DefaultOwner %q", testUsername, DefaultOwner)
	}
}

// --- Partial-failure tests using request-log assertion strategy ---

// recordedRequests tracks "METHOD /path" strings under a mutex so the
// httptest handler (called from a different goroutine) can append safely.
type recordedRequests struct {
	mu      sync.Mutex
	entries []string
}

func (r *recordedRequests) record(req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, req.Method+" "+req.URL.Path)
}

func (r *recordedRequests) has(method, pathSubstr string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.entries {
		if e == method+" "+pathSubstr || strings.Contains(e, method+" ") && strings.Contains(e, pathSubstr) {
			return true
		}
	}
	return false
}

// TestCreateForkFilePR_GetContentsFails verifies that when step 6
// (getContentsFor) returns 500, the cleanup DELETE refs request is recorded.
// Branch creation (step 5) succeeds before the failure.
func TestCreateForkFilePR_GetContentsFails(t *testing.T) {
	withForkOverrides(t, 0, 1)

	var reqs recordedRequests

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs.record(r)

		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/forks"):
			w.WriteHeader(202)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/repos/testuser/") &&
			!strings.Contains(r.URL.Path, "/git/") && !strings.Contains(r.URL.Path, "/contents/"):
			// waitForFork poll — fork ready immediately.
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
			// Step 5: branch creation succeeds.
			w.WriteHeader(201)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/contents/"):
			// Step 6: getContentsFor fails.
			w.WriteHeader(500)
			w.Write([]byte(`{"message": "Internal Server Error"}`))

		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/git/refs/"):
			// Cleanup DELETE — succeed.
			w.WriteHeader(204)

		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	c := newTestClientWithUser(srv, "tok", "testuser")
	_, err := c.createForkFilePR(context.Background(), "path.json", []byte("data"), "prefix-", "title", "body")
	if err == nil {
		t.Fatal("expected error when getContentsFor fails")
	}
	if !strings.Contains(err.Error(), "getting file SHA from fork") {
		t.Errorf("error = %q, want to contain 'getting file SHA from fork'", err.Error())
	}

	// Cleanup runs synchronously inside createForkFilePR before it returns,
	// but give a small margin in case of any scheduler delay.
	time.Sleep(50 * time.Millisecond)

	if !reqs.has(http.MethodDelete, "/git/refs/") {
		t.Error("expected DELETE /git/refs/ recorded for cleanup, but not found")
	}
}

// TestCreateForkFilePR_CreatePRFails verifies that when step 8
// (createPRFor) returns 500, the cleanup DELETE refs request is recorded.
// File update (step 7) succeeds before the failure.
func TestCreateForkFilePR_CreatePRFails(t *testing.T) {
	withForkOverrides(t, 0, 1)

	var reqs recordedRequests

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs.record(r)

		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/forks"):
			w.WriteHeader(202)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/repos/testuser/") &&
			!strings.Contains(r.URL.Path, "/git/") && !strings.Contains(r.URL.Path, "/contents/"):
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
			// Step 5: branch creation succeeds.
			w.WriteHeader(201)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/contents/"):
			// Step 6: getContentsFor succeeds.
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]string{"sha": "fsha"})

		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/contents/"):
			// Step 7: file update succeeds.
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/pulls"):
			// Step 8: createPR fails.
			w.WriteHeader(500)
			w.Write([]byte(`{"message": "Internal Server Error"}`))

		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/git/refs/"):
			// Cleanup DELETE — succeed.
			w.WriteHeader(204)

		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	c := newTestClientWithUser(srv, "tok", "testuser")
	_, err := c.createForkFilePR(context.Background(), "path.json", []byte("data"), "prefix-", "title", "body")
	if err == nil {
		t.Fatal("expected error when createPR fails")
	}
	if !strings.Contains(err.Error(), "creating pull request") {
		t.Errorf("error = %q, want to contain 'creating pull request'", err.Error())
	}

	time.Sleep(50 * time.Millisecond)

	if !reqs.has(http.MethodDelete, "/git/refs/") {
		t.Error("expected DELETE /git/refs/ recorded for cleanup, but not found")
	}
}

// TestCreateForkFilePR_ForkPollTimeout verifies that when the fork poll
// always returns 404 (times out), an error is returned and no branch-creation
// POST /git/refs request was recorded (cleanup never runs because no branch
// was created).
func TestCreateForkFilePR_ForkPollTimeout(t *testing.T) {
	// Use 3 poll attempts with zero interval so the test completes quickly.
	withForkOverrides(t, 0, 3)

	var reqs recordedRequests

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs.record(r)

		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/forks"):
			w.WriteHeader(202)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/repos/testuser/") &&
			!strings.Contains(r.URL.Path, "/git/"):
			// Fork poll — always 404 so the poll exhausts all attempts.
			w.WriteHeader(404)
			w.Write([]byte(`{"message": "Not Found"}`))

		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	c := newTestClientWithUser(srv, "tok", "testuser")
	_, err := c.createForkFilePR(context.Background(), "path.json", []byte("data"), "prefix-", "title", "body")
	if err == nil {
		t.Fatal("expected error when fork poll times out")
	}
	if !IsForkError(err) {
		t.Errorf("expected ForkError, got %T: %v", err, err)
	}

	// No branch was created — POST /git/refs must not appear in the request log.
	reqs.mu.Lock()
	defer reqs.mu.Unlock()
	for _, e := range reqs.entries {
		if e == http.MethodPost+" /repos/testuser/"+DefaultRepo+"/git/refs" {
			t.Errorf("unexpected branch-creation request recorded: %q", e)
		}
	}
}

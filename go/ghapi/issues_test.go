package ghapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreateIssue_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		wantPath := "/repos/" + DefaultOwner + "/" + DefaultRepo + "/issues"
		if r.URL.Path != wantPath {
			t.Errorf("path = %q, want %q", r.URL.Path, wantPath)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer test-token")
		}

		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("unmarshal request: %v", err)
		}
		if req["title"] != "Test Issue" {
			t.Errorf("title = %v, want %q", req["title"], "Test Issue")
		}
		if req["body"] != "Issue body" {
			t.Errorf("body = %v, want %q", req["body"], "Issue body")
		}
		labels, ok := req["labels"].([]any)
		if !ok || len(labels) != 2 {
			t.Fatalf("labels = %v, want [\"bug\", \"urgent\"]", req["labels"])
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(IssueResult{
			Number:  42,
			HTMLURL: "https://github.com/test/repo/issues/42",
		})
	}))
	defer ts.Close()

	c := NewClient("test-token")
	c.BaseURL = ts.URL

	result, err := c.CreateIssue(context.Background(), "Test Issue", "Issue body", []string{"bug", "urgent"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Number != 42 {
		t.Errorf("Number = %d, want 42", result.Number)
	}
	if result.HTMLURL != "https://github.com/test/repo/issues/42" {
		t.Errorf("HTMLURL = %q, want %q", result.HTMLURL, "https://github.com/test/repo/issues/42")
	}
}

func TestCreateIssue_Unauthorized(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message": "Bad credentials"}`))
	}))
	defer ts.Close()

	c := NewClient("bad-token")
	c.BaseURL = ts.URL

	_, err := c.CreateIssue(context.Background(), "Title", "Body", nil)
	if err == nil {
		t.Fatal("expected error for 401")
	}
	if !IsUnauthorized(err) {
		t.Errorf("expected IsUnauthorized, got: %v", err)
	}
}

func TestCreateIssue_Forbidden(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message": "Resource not accessible by integration"}`))
	}))
	defer ts.Close()

	c := NewClient("test-token")
	c.BaseURL = ts.URL

	_, err := c.CreateIssue(context.Background(), "Title", "Body", nil)
	if err == nil {
		t.Fatal("expected error for 403")
	}
	if !IsForbidden(err) {
		t.Errorf("expected IsForbidden, got: %v", err)
	}
}

func TestCreateIssue_ValidationError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(`{"message": "Validation Failed"}`))
	}))
	defer ts.Close()

	c := NewClient("test-token")
	c.BaseURL = ts.URL

	_, err := c.CreateIssue(context.Background(), "Title", "Body", []string{"bug"})
	if err == nil {
		t.Fatal("expected error for 422")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != 422 {
		t.Errorf("StatusCode = %d, want 422", apiErr.StatusCode)
	}
	if !strings.Contains(apiErr.Message, "Validation Failed") {
		t.Errorf("Message = %q, want to contain %q", apiErr.Message, "Validation Failed")
	}
}

func TestCreateIssue_NetworkError(t *testing.T) {
	// Use a server that's already closed to trigger a connection error.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ts.Close()

	c := NewClient("test-token")
	c.BaseURL = ts.URL

	_, err := c.CreateIssue(context.Background(), "Title", "Body", nil)
	if err == nil {
		t.Fatal("expected network error")
	}
	// Network errors should NOT be APIError.
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		t.Errorf("expected non-APIError for network failure, got APIError: %v", apiErr)
	}
}

func TestCreateIssue_TitleTruncation(t *testing.T) {
	longTitle := strings.Repeat("A", 300)

	var receivedTitle string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		json.Unmarshal(body, &req)
		receivedTitle = req["title"].(string)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(IssueResult{Number: 1, HTMLURL: "https://example.com/1"})
	}))
	defer ts.Close()

	c := NewClient("test-token")
	c.BaseURL = ts.URL

	_, err := c.CreateIssue(context.Background(), longTitle, "Body", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(receivedTitle) != maxIssueTitle {
		t.Errorf("received title length = %d, want %d", len(receivedTitle), maxIssueTitle)
	}
	if receivedTitle != strings.Repeat("A", maxIssueTitle) {
		t.Error("truncated title content mismatch")
	}
}

func TestCreateIssue_MultibyteTitleTruncation(t *testing.T) {
	// Place a 4-byte emoji so the 256-byte cut falls mid-rune.
	filler := strings.Repeat("A", maxIssueTitle-2)
	longTitle := filler + "\U0001F600" // 4-byte emoji, cut after 2 bytes

	var receivedTitle string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		json.Unmarshal(body, &req)
		receivedTitle = req["title"].(string)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(IssueResult{Number: 1, HTMLURL: "https://example.com/1"})
	}))
	defer ts.Close()

	c := NewClient("test-token")
	c.BaseURL = ts.URL

	_, err := c.CreateIssue(context.Background(), longTitle, "Body", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(receivedTitle) > maxIssueTitle {
		t.Errorf("title length = %d, exceeds %d", len(receivedTitle), maxIssueTitle)
	}
	if strings.ToValidUTF8(receivedTitle, "\xff") != receivedTitle {
		t.Error("truncated title is not valid UTF-8")
	}
}

func TestCreateIssue_ShortTitleNotTruncated(t *testing.T) {
	shortTitle := "Short title"

	var receivedTitle string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		json.Unmarshal(body, &req)
		receivedTitle = req["title"].(string)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(IssueResult{Number: 1, HTMLURL: "https://example.com/1"})
	}))
	defer ts.Close()

	c := NewClient("test-token")
	c.BaseURL = ts.URL

	_, err := c.CreateIssue(context.Background(), shortTitle, "Body", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedTitle != shortTitle {
		t.Errorf("title = %q, want %q", receivedTitle, shortTitle)
	}
}

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
	"slices"
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

// --- baseURL tests ---

func TestClient_baseURL_Default(t *testing.T) {
	c := NewClient("tok")
	if got := c.baseURL(); got != defaultAPIBaseURL {
		t.Errorf("baseURL() = %q, want %q", got, defaultAPIBaseURL)
	}
}

func TestClient_baseURL_Override(t *testing.T) {
	c := NewClient("tok")
	c.BaseURL = "http://localhost:9999"
	if got := c.baseURL(); got != "http://localhost:9999" {
		t.Errorf("baseURL() = %q, want %q", got, "http://localhost:9999")
	}
}

func TestClient_baseURL_EmptyStringUsesDefault(t *testing.T) {
	c := &Client{BaseURL: ""}
	if got := c.baseURL(); got != defaultAPIBaseURL {
		t.Errorf("baseURL() = %q, want %q", got, defaultAPIBaseURL)
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

// --- CreateRegistryPR (flow tests live in pr_test.go) ---

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

// --- CreateRevocationPR ---

const (
	testRevHashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testRevHashB = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
)

// wrappedBase64 encodes data as the GitHub contents API does: standard
// base64 with a newline every 60 characters.
func wrappedBase64(data []byte) string {
	enc := base64.StdEncoding.EncodeToString(data)
	var sb strings.Builder
	for len(enc) > 60 {
		sb.WriteString(enc[:60])
		sb.WriteByte('\n')
		enc = enc[60:]
	}
	sb.WriteString(enc)
	sb.WriteByte('\n')
	return sb.String()
}

// revocationFake records the requests a fake GitHub server received during a
// CreateRevocationPR run.
type revocationFake struct {
	calls        []string
	contentsGETs []string // path?query of every contents GET
	putContent   []byte   // decoded content of the PUT
	branchRef    string
	prTitle      string
	prBody       string
	pullsGET     string // path?query of the open-PR list GET

	// Response for the open-PR list GET; tests may override after construction.
	pullsStatus int
	pullsBody   string
	// Body of the GET /repos/{owner}/{repo} access check (always 200).
	repoBody string
}

// newRevocationFakeServer serves a full same-repo PR flow. Every contents GET
// (the upstream fetch and the branch blob-SHA lookup) returns upstream,
// line-wrapped.
func newRevocationFakeServer(t *testing.T, upstream []byte) (*httptest.Server, *revocationFake) {
	t.Helper()
	f := &revocationFake{pullsStatus: 200, pullsBody: `[]`, repoBody: `{"permissions": {"push": true}}`}
	repoPath := "/repos/" + DefaultOwner + "/" + DefaultRepo
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == repoPath:
			f.calls = append(f.calls, "repoAccess")
			w.WriteHeader(200)
			w.Write([]byte(f.repoBody))

		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/pulls"):
			f.calls = append(f.calls, "listPulls")
			f.pullsGET = r.URL.Path + "?" + r.URL.RawQuery
			w.WriteHeader(f.pullsStatus)
			w.Write([]byte(f.pullsBody))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/git/refs/heads/main"):
			f.calls = append(f.calls, "getRef")
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]any{
				"ref":    "refs/heads/main",
				"object": map[string]string{"sha": "main-sha-000"},
			})

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/refs"):
			f.calls = append(f.calls, "createRef")
			body, _ := io.ReadAll(r.Body)
			var req map[string]string
			json.Unmarshal(body, &req)
			f.branchRef = req["ref"]
			w.WriteHeader(201)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/contents/"):
			f.calls = append(f.calls, "getContents")
			f.contentsGETs = append(f.contentsGETs, r.URL.Path+"?"+r.URL.RawQuery)
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]string{
				"content":  wrappedBase64(upstream),
				"encoding": "base64",
				"sha":      "file-sha-rev",
			})

		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/contents/"):
			f.calls = append(f.calls, "updateContents")
			if !strings.Contains(r.URL.Path, "revocations.json") {
				t.Errorf("PUT path = %s, want to contain revocations.json", r.URL.Path)
			}
			body, _ := io.ReadAll(r.Body)
			var req map[string]string
			json.Unmarshal(body, &req)
			decoded, err := base64.StdEncoding.DecodeString(req["content"])
			if err != nil {
				t.Errorf("PUT content not valid base64: %v", err)
			}
			f.putContent = decoded
			w.WriteHeader(200)
			w.Write([]byte(`{}`))

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/pulls"):
			f.calls = append(f.calls, "createPR")
			body, _ := io.ReadAll(r.Body)
			var req map[string]string
			json.Unmarshal(body, &req)
			f.prTitle = req["title"]
			f.prBody = req["body"]
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(PRResult{Number: 99, HTMLURL: "https://github.com/test/pr/99"})

		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, f
}

func TestCreateRevocationPR_Success(t *testing.T) {
	upstream := []byte(`{"revocations": []}`)
	srv, f := newRevocationFakeServer(t, upstream)

	c := newTestClient(srv, "tok")
	pr, err := c.CreateRevocationPR(context.Background(), testRevHashB, "2026-10-01")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pr.Number != 99 {
		t.Errorf("PR number = %d, want 99", pr.Number)
	}
	if pr.HTMLURL != "https://github.com/test/pr/99" {
		t.Errorf("PR URL = %q, want https://github.com/test/pr/99", pr.HTMLURL)
	}

	// Upstream fetch and the pending-PR check happen before any write work.
	expected := []string{"getContents", "listPulls", "repoAccess", "getRef", "createRef", "getContents", "updateContents", "createPR"}
	if len(f.calls) != len(expected) {
		t.Fatalf("call sequence = %v, want %v", f.calls, expected)
	}
	for i, want := range expected {
		if f.calls[i] != want {
			t.Errorf("call[%d] = %q, want %q", i, f.calls[i], want)
		}
	}

	if !strings.Contains(f.branchRef, "revoke-") {
		t.Errorf("branch ref = %q, want to contain 'revoke-'", f.branchRef)
	}
	wantPulls := "/repos/" + DefaultOwner + "/" + DefaultRepo + "/pulls?per_page=100&state=open"
	if f.pullsGET != wantPulls {
		t.Errorf("open-PR list GET = %q, want %q", f.pullsGET, wantPulls)
	}
	for _, p := range f.contentsGETs {
		if !strings.Contains(p, "revocations.json") {
			t.Errorf("contents GET = %q, want to contain revocations.json", p)
		}
	}

	// PUT body is exactly upstream + the new entry, in the canonical format.
	want := "{\n  \"revocations\": [\n    {\n      \"hash\": \"" + testRevHashB + "\",\n      \"revoked_on\": \"2026-10-01\"\n    }\n  ]\n}\n"
	if string(f.putContent) != want {
		t.Errorf("PUT content =\n%s\nwant\n%s", f.putContent, want)
	}

	shortHash := testRevHashB[:16]
	if !strings.Contains(f.prTitle, "Revoke credential") || !strings.Contains(f.prTitle, shortHash) {
		t.Errorf("PR title = %q, want 'Revoke credential' and %q", f.prTitle, shortHash)
	}
	if !strings.Contains(f.prBody, testRevHashB) {
		t.Errorf("PR body = %q, want to contain full hash %q", f.prBody, testRevHashB)
	}
}

// TestCreateRevocationPR_PreservesUpstreamEntries guards against building the
// new file from a stale local copy: an entry merged upstream (A) must survive
// a later revocation (B).
func TestCreateRevocationPR_PreservesUpstreamEntries(t *testing.T) {
	upstream, err := json.MarshalIndent(core.RevocationList{Revocations: []core.RevocationEntry{
		{Hash: testRevHashA, RevokedOn: "2026-09-30"},
	}}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if len(base64.StdEncoding.EncodeToString(upstream)) <= 60 {
		t.Fatal("fixture too small to exercise line-wrapped base64")
	}
	srv, f := newRevocationFakeServer(t, upstream)

	c := newTestClient(srv, "tok")
	if _, err := c.CreateRevocationPR(context.Background(), testRevHashB, "2026-10-01"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(f.contentsGETs) == 0 {
		t.Fatal("no contents GET recorded")
	}
	wantUpstream := "/repos/" + DefaultOwner + "/" + DefaultRepo + "/contents/" + revocationPath + "?ref=main"
	if f.contentsGETs[0] != wantUpstream {
		t.Errorf("upstream GET = %q, want %q", f.contentsGETs[0], wantUpstream)
	}

	got, err := core.ValidateRevocationList(f.putContent)
	if err != nil {
		t.Fatalf("PUT content is not a valid revocation list: %v\n%s", err, f.putContent)
	}
	wantEntries := []core.RevocationEntry{
		{Hash: testRevHashA, RevokedOn: "2026-09-30"},
		{Hash: testRevHashB, RevokedOn: "2026-10-01"},
	}
	if len(got.Revocations) != len(wantEntries) {
		t.Fatalf("PUT entries = %v, want %v", got.Revocations, wantEntries)
	}
	for i, w := range wantEntries {
		if got.Revocations[i] != w {
			t.Errorf("entry[%d] = %v, want %v", i, got.Revocations[i], w)
		}
	}
}

func TestCreateRevocationPR_BranchUsesShortHash(t *testing.T) {
	srv, f := newRevocationFakeServer(t, []byte(`{"revocations": []}`))

	c := newTestClient(srv, "tok")
	if _, err := c.CreateRevocationPR(context.Background(), testRevHashB, "2026-10-01"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Branch ref should contain "revoke-" followed by exactly 16 hex chars, then "-".
	expectedPrefix := "revoke-" + testRevHashB[:16] + "-"
	if !strings.Contains(f.branchRef, expectedPrefix) {
		t.Errorf("branch ref = %q, want to contain %q", f.branchRef, expectedPrefix)
	}
	if strings.Contains(f.branchRef, testRevHashB) {
		t.Errorf("branch ref = %q, should not contain full hash", f.branchRef)
	}
}

func TestCreateRevocationPR_AlreadyRevoked(t *testing.T) {
	upstream := []byte(`{"revocations": [{"hash": "` + testRevHashB + `", "revoked_on": "2026-09-30"}]}`)
	srv, f := newRevocationFakeServer(t, upstream)

	c := newTestClient(srv, "tok")
	_, err := c.CreateRevocationPR(context.Background(), strings.ToUpper(testRevHashB), "2026-10-01")
	if !errors.Is(err, ErrAlreadyRevoked) {
		t.Fatalf("error = %v, want ErrAlreadyRevoked", err)
	}
	if len(f.calls) != 1 || f.calls[0] != "getContents" {
		t.Errorf("calls = %v, want only the upstream getContents", f.calls)
	}
}

func TestCreateRevocationPR_OpenPRCheck(t *testing.T) {
	ref := revocationBranchPrefix(testRevHashB) + "abc"
	thisRepo := DefaultOwner + "/" + DefaultRepo
	cases := []struct {
		name        string
		status      int
		body        string
		wantPending bool
	}{
		{"same-repo open PR", 200, `[{"head": {"ref": "` + ref + `", "repo": {"full_name": "` + thisRepo + `"}}}]`, true},
		{"fork PR with same ref", 200, `[{"head": {"ref": "` + ref + `", "repo": {"full_name": "someone/` + DefaultRepo + `"}}}]`, false},
		{"lookup fails (fail open)", 500, `{"message": "boom"}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, f := newRevocationFakeServer(t, []byte(`{"revocations": []}`))
			f.pullsStatus, f.pullsBody = tc.status, tc.body

			c := newTestClient(srv, "tok")
			pr, err := c.CreateRevocationPR(context.Background(), testRevHashB, "2026-10-01")
			if tc.wantPending {
				if !errors.Is(err, ErrRevocationPending) {
					t.Fatalf("error = %v, want ErrRevocationPending", err)
				}
				if slices.Contains(f.calls, "repoAccess") || slices.Contains(f.calls, "createPR") {
					t.Errorf("calls = %v, want no PR work", f.calls)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if pr.Number != 99 {
				t.Errorf("PR number = %d, want 99", pr.Number)
			}
			if !slices.Contains(f.calls, "listPulls") || !slices.Contains(f.calls, "createPR") {
				t.Errorf("calls = %v, want listPulls and createPR", f.calls)
			}
		})
	}
}

func TestCreateRevocationPR_NoWriteAccess(t *testing.T) {
	srv, f := newRevocationFakeServer(t, []byte(`{"revocations": []}`))
	f.repoBody = `{"permissions": {"push": false}}`

	c := newTestClient(srv, "tok")
	_, err := c.CreateRevocationPR(context.Background(), testRevHashB, "2026-10-01")
	if !errors.Is(err, ErrNoWriteAccess) {
		t.Fatalf("error = %v, want ErrNoWriteAccess", err)
	}
	if slices.Contains(f.calls, "createRef") || slices.Contains(f.calls, "createPR") {
		t.Errorf("calls = %v, want no branch or PR work", f.calls)
	}
}

func TestCreateRevocationPR_InvalidHash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("API should not be called for invalid hash: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(500)
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	cases := map[string]string{
		"empty":    "",
		"short":    "abc123",
		"too long": testRevHashB + "0",
		"non-hex":  strings.Repeat("g", 64),
		"newline":  testRevHashB[:63] + "\n",
	}
	for name, hash := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := c.CreateRevocationPR(context.Background(), hash, "2026-10-01")
			if err == nil {
				t.Fatal("expected error for invalid hash")
			}
			if !strings.Contains(err.Error(), "invalid payload hash") {
				t.Errorf("error = %q, want to contain 'invalid payload hash'", err.Error())
			}
		})
	}
}

func TestCreateRevocationPR_UpstreamFetchFails(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(404)
		w.Write([]byte(`{"message":"Not Found"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	_, err := c.CreateRevocationPR(context.Background(), testRevHashB, "2026-10-01")
	if err == nil {
		t.Fatal("expected error when upstream fetch fails")
	}
	if !strings.Contains(err.Error(), "fetching upstream revocation list") {
		t.Errorf("error = %q, want fetch context", err.Error())
	}
	var ae *APIError
	if !errors.As(err, &ae) || ae.StatusCode != 404 {
		t.Errorf("error = %v, want wrapped 404 APIError", err)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("API calls = %d, want 1 (no PR work after failed fetch)", n)
	}
}

func TestCreateRevocationPR_UpstreamInvalid(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		json.NewEncoder(w).Encode(map[string]string{
			"content":  base64.StdEncoding.EncodeToString([]byte(`{"revocations": [{"hash": "bad", "revoked_on": "2026-01-01"}]}`)),
			"encoding": "base64",
		})
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	_, err := c.CreateRevocationPR(context.Background(), testRevHashB, "2026-10-01")
	if err == nil {
		t.Fatal("expected error for invalid upstream list")
	}
	if !strings.Contains(err.Error(), "validating upstream revocation list") {
		t.Errorf("error = %q, want validation context", err.Error())
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("API calls = %d, want 1 (no PR work after invalid list)", n)
	}
}

// --- FetchUpstreamFile ---

func TestFetchUpstreamFile_DecodesWrappedBase64(t *testing.T) {
	want := []byte(strings.Repeat("0123456789", 20)) // encodes to >60 chars
	var gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		json.NewEncoder(w).Encode(map[string]string{
			"content":  wrappedBase64(want),
			"encoding": "base64",
			"sha":      "abc",
		})
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	got, err := c.FetchUpstreamFile(context.Background(), revocationPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("content = %q, want %q", got, want)
	}
	if wantPath := "/repos/" + DefaultOwner + "/" + DefaultRepo + "/contents/" + revocationPath; gotPath != wantPath {
		t.Errorf("path = %q, want %q", gotPath, wantPath)
	}
	if gotQuery != "ref=main" {
		t.Errorf("query = %q, want ref=main", gotQuery)
	}
}

func TestFetchUpstreamFile_NonBase64Encoding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"content": "", "encoding": "none", "sha": "abc"})
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	_, err := c.FetchUpstreamFile(context.Background(), revocationPath)
	if err == nil {
		t.Fatal("expected error for encoding \"none\"")
	}
	if !strings.Contains(err.Error(), "unsupported content encoding") {
		t.Errorf("error = %q, want 'unsupported content encoding'", err.Error())
	}
}

func TestFetchUpstreamFile_InvalidBase64(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"content": "!!!not-base64!!!", "encoding": "base64"})
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	_, err := c.FetchUpstreamFile(context.Background(), revocationPath)
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
	if !strings.Contains(err.Error(), "decoding") {
		t.Errorf("error = %q, want decoding context", err.Error())
	}
}

func TestFetchUpstreamFile_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte(`{"message":"Not Found"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	_, err := c.FetchUpstreamFile(context.Background(), revocationPath)
	var ae *APIError
	if !errors.As(err, &ae) || ae.StatusCode != 404 {
		t.Errorf("error = %v, want 404 APIError", err)
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

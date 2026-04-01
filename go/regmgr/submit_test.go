package regmgr

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
)

// rewriteTransport redirects all requests to the httptest server, replacing
// the scheme+host while preserving path and query.
type rewriteTransport struct {
	base      http.RoundTripper
	targetURL string
}

func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = strings.TrimPrefix(t.targetURL, "http://")
	return t.base.RoundTrip(req)
}

// TestSubmitForReview_Integration validates the MarshalRegistry → CreateRegistryPR pipeline
// using an httptest server that mocks the full fork-based PR flow.
func TestSubmitForReview_Integration(t *testing.T) {
	// 1. Build a valid registry with one entry using a real Ed25519 key.
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating Ed25519 key: %v", err)
	}
	pubKeyBytes := priv.Public().(ed25519.PublicKey)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKeyBytes)

	to := "2027-12-31"
	reg := core.Registry{Keys: []core.KeyEntry{{
		Authority: "Test Authority",
		Algorithm: "Ed25519",
		PublicKey: pubKeyB64,
		From:      "2026-01-01",
		To:        &to,
		Note:      "integration test key",
	}}}

	// 2. Marshal via MarshalRegistry.
	content, err := MarshalRegistry(reg)
	if err != nil {
		t.Fatalf("MarshalRegistry: %v", err)
	}
	if len(content) == 0 {
		t.Fatal("MarshalRegistry returned empty content")
	}

	// 3. Set up httptest server mocking the fork flow endpoints.
	owner := ghapi.DefaultOwner
	repo := ghapi.DefaultRepo
	username := "testuser"

	var putBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		method := r.Method

		switch {
		// POST /repos/{owner}/{repo}/forks → 202 (fork created)
		case method == http.MethodPost && path == fmt.Sprintf("/repos/%s/%s/forks", owner, repo):
			w.WriteHeader(http.StatusAccepted)
			fmt.Fprintf(w, `{"full_name":"%s/%s"}`, username, repo)

		// GET /repos/{username}/{repo} → 200 (fork ready)
		case method == http.MethodGet && path == fmt.Sprintf("/repos/%s/%s", username, repo):
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"full_name":"%s/%s"}`, username, repo)

		// POST /repos/{username}/{repo}/merge-upstream → 200 (sync done)
		case method == http.MethodPost && path == fmt.Sprintf("/repos/%s/%s/merge-upstream", username, repo):
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"message":"Successfully fetched and fast-forwarded from upstream"}`)

		// GET /repos/{username}/{repo}/git/refs/heads/main → 200 with SHA
		case method == http.MethodGet && path == fmt.Sprintf("/repos/%s/%s/git/refs/heads/main", username, repo):
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"object":{"sha":"abc123deadbeef"}}`)

		// POST /repos/{username}/{repo}/git/refs → 201 (branch created)
		case method == http.MethodPost && path == fmt.Sprintf("/repos/%s/%s/git/refs", username, repo):
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"ref":"refs/heads/registry-update-branch"}`)

		// GET /repos/{username}/{repo}/contents/{path}?ref=main → 200 with file SHA
		case method == http.MethodGet && strings.HasPrefix(path, fmt.Sprintf("/repos/%s/%s/contents/", username, repo)):
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"sha":"existingfilesha456"}`)

		// PUT /repos/{username}/{repo}/contents/{path} → 200 (file updated)
		case method == http.MethodPut && strings.HasPrefix(path, fmt.Sprintf("/repos/%s/%s/contents/", username, repo)):
			body, readErr := io.ReadAll(r.Body)
			if readErr != nil {
				http.Error(w, "failed to read body", http.StatusInternalServerError)
				return
			}
			putBody = body
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"content":{"sha":"newfilesha789"}}`)

		// POST /repos/{owner}/{repo}/pulls → 201 with PR number + URL
		case method == http.MethodPost && path == fmt.Sprintf("/repos/%s/%s/pulls", owner, repo):
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"number":42,"html_url":"https://github.com/%s/%s/pull/42"}`, owner, repo)

		default:
			t.Errorf("unexpected request: %s %s", method, path)
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	// 4. Create client pointed at test server.
	client := ghapi.NewClientWithUser("test-token", username)
	client.HTTPClient = srv.Client()
	client.HTTPClient.Transport = &rewriteTransport{
		base:      srv.Client().Transport,
		targetURL: srv.URL,
	}

	// 5. Call CreateRegistryPR.
	pr, err := client.CreateRegistryPR(context.Background(), content, "Test PR")
	if err != nil {
		t.Fatalf("CreateRegistryPR: %v", err)
	}

	// 6. Assert PR result.
	if pr.Number != 42 {
		t.Errorf("PR number = %d, want 42", pr.Number)
	}
	expectedURL := fmt.Sprintf("https://github.com/%s/%s/pull/42", owner, repo)
	if pr.HTMLURL != expectedURL {
		t.Errorf("PR URL = %q, want %q", pr.HTMLURL, expectedURL)
	}

	// 7. Assert PUT body: decode JSON, extract "content" field, base64-decode it,
	// and compare to the MarshalRegistry output.
	if len(putBody) == 0 {
		t.Fatal("PUT body was not captured")
	}

	var putPayload struct {
		Message string `json:"message"`
		Content string `json:"content"`
		Branch  string `json:"branch"`
		SHA     string `json:"sha"`
	}
	if err := json.Unmarshal(putBody, &putPayload); err != nil {
		t.Fatalf("unmarshaling PUT body: %v", err)
	}

	if putPayload.SHA != "existingfilesha456" {
		t.Errorf("PUT sha = %q, want %q", putPayload.SHA, "existingfilesha456")
	}
	if putPayload.Branch == "" {
		t.Error("PUT branch is empty")
	}
	if putPayload.Message == "" {
		t.Error("PUT message is empty")
	}

	decoded, err := base64.StdEncoding.DecodeString(putPayload.Content)
	if err != nil {
		t.Fatalf("decoding PUT content from base64: %v", err)
	}

	if string(decoded) != string(content) {
		t.Errorf("PUT content mismatch:\ngot:  %s\nwant: %s", string(decoded), string(content))
	}
}

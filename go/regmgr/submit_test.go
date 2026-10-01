package regmgr

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

// testKeyEntry returns a valid registry entry backed by a fresh Ed25519 key.
func testKeyEntry(t *testing.T, authority string, to *string) core.KeyEntry {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating Ed25519 key: %v", err)
	}
	return core.KeyEntry{
		Authority: authority,
		Algorithm: "Ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		From:      "2026-01-01",
		To:        to,
		Note:      "submit test key",
	}
}

// submitFake is an httptest GitHub API covering the upstream registry read
// and the fork-based PR flow. It records every "METHOD path" it serves.
type submitFake struct {
	mu   sync.Mutex
	hits []string
}

func (f *submitFake) hitList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.hits...)
}

// newSubmitFake starts the fake. upstream is served as the upstream main
// registry.json; upstreamStatus != 200 makes that GET fail instead.
func newSubmitFake(t *testing.T, username string, upstream []byte, upstreamStatus int) (*submitFake, *ghapi.Client) {
	t.Helper()
	owner, repo := ghapi.DefaultOwner, ghapi.DefaultRepo
	upstreamPath := fmt.Sprintf("/repos/%s/%s/contents/%s", owner, repo, ghapi.RegistryFilePath)
	forkPrefix := fmt.Sprintf("/repos/%s/%s", username, repo)
	f := &submitFake{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, method := r.URL.Path, r.Method
		f.mu.Lock()
		f.hits = append(f.hits, method+" "+path)
		f.mu.Unlock()

		switch {
		case method == http.MethodGet && path == upstreamPath:
			if r.URL.Query().Get("ref") != "main" {
				t.Errorf("upstream GET ref = %q, want main", r.URL.Query().Get("ref"))
			}
			if upstreamStatus != http.StatusOK {
				w.WriteHeader(upstreamStatus)
				fmt.Fprint(w, `{"message":"boom"}`)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"content":  base64.StdEncoding.EncodeToString(upstream),
				"encoding": "base64",
				"sha":      "upstreamsha123",
			})
		case method == http.MethodPost && path == fmt.Sprintf("/repos/%s/%s/forks", owner, repo):
			w.WriteHeader(http.StatusAccepted)
			fmt.Fprintf(w, `{"full_name":"%s/%s"}`, username, repo)
		case method == http.MethodGet && path == forkPrefix:
			fmt.Fprintf(w, `{"full_name":"%s/%s"}`, username, repo)
		case method == http.MethodPost && path == forkPrefix+"/merge-upstream":
			fmt.Fprint(w, `{"message":"ok"}`)
		case method == http.MethodGet && path == forkPrefix+"/git/refs/heads/main":
			fmt.Fprint(w, `{"object":{"sha":"abc123deadbeef"}}`)
		case method == http.MethodPost && path == forkPrefix+"/git/refs":
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"ref":"refs/heads/registry-update-branch"}`)
		case method == http.MethodGet && strings.HasPrefix(path, forkPrefix+"/contents/"):
			fmt.Fprint(w, `{"sha":"existingfilesha456"}`)
		case method == http.MethodPut && strings.HasPrefix(path, forkPrefix+"/contents/"):
			fmt.Fprint(w, `{"content":{"sha":"newfilesha789"}}`)
		case method == http.MethodPost && path == fmt.Sprintf("/repos/%s/%s/pulls", owner, repo):
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"number":7,"html_url":"https://github.com/%s/%s/pull/7"}`, owner, repo)
		default:
			t.Errorf("unexpected request: %s %s", method, path)
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	client := ghapi.NewClientWithUser("test-token", username)
	client.HTTPClient = srv.Client()
	client.HTTPClient.Transport = &rewriteTransport{base: srv.Client().Transport, targetURL: srv.URL}
	return f, client
}

// upstreamOnly asserts the fake saw exactly the upstream registry GET — no
// fork, ref, PUT or pulls call.
func upstreamOnly(t *testing.T, f *submitFake) {
	t.Helper()
	want := fmt.Sprintf("GET /repos/%s/%s/contents/%s", ghapi.DefaultOwner, ghapi.DefaultRepo, ghapi.RegistryFilePath)
	hits := f.hitList()
	if len(hits) != 1 || hits[0] != want {
		t.Errorf("hits = %v, want only [%s]", hits, want)
	}
}

func TestSubmitRegistry_UpstreamUnchanged_CreatesPR(t *testing.T) {
	to := "2027-12-31"
	reg := core.Registry{Keys: []core.KeyEntry{testKeyEntry(t, "Key X", &to), testKeyEntry(t, "Key Y", nil)}}
	base, err := MarshalRegistry(reg)
	if err != nil {
		t.Fatalf("MarshalRegistry: %v", err)
	}
	// Upstream is the same registry in compact form with CRLF line endings:
	// formatting differences must not count as a change.
	compact, err := json.Marshal(reg)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	upstream := append(compact, '\r', '\n')

	edited := reg
	edited.Keys = append([]core.KeyEntry(nil), reg.Keys...)
	edited.Keys[1].Note = "edited"
	content, err := MarshalRegistry(edited)
	if err != nil {
		t.Fatalf("MarshalRegistry: %v", err)
	}

	f, client := newSubmitFake(t, "testuser", upstream, http.StatusOK)
	pr, err := submitRegistry(context.Background(), client, base, content, "Registry update")
	if err != nil {
		t.Fatalf("submitRegistry: %v", err)
	}
	if pr.Number != 7 {
		t.Errorf("PR number = %d, want 7", pr.Number)
	}
	hits := f.hitList()
	if len(hits) < 2 || !strings.Contains(hits[0], "/contents/"+ghapi.RegistryFilePath) {
		t.Errorf("first request should be the upstream registry GET, hits = %v", hits)
	}
	if last := hits[len(hits)-1]; !strings.HasSuffix(last, "/pulls") {
		t.Errorf("last request = %q, want the pulls POST", last)
	}
}

func TestSubmitRegistry_UpstreamChanged_Refuses(t *testing.T) {
	reg := core.Registry{Keys: []core.KeyEntry{testKeyEntry(t, "Key X", nil), testKeyEntry(t, "Key Y", nil)}}
	base, err := MarshalRegistry(reg)
	if err != nil {
		t.Fatalf("MarshalRegistry: %v", err)
	}
	// Another PR merged since the fetch and revoked key X.
	revoked := "2026-09-30"
	merged := reg
	merged.Keys = append([]core.KeyEntry(nil), reg.Keys...)
	merged.Keys[0].To = &revoked
	upstream, err := MarshalRegistry(merged)
	if err != nil {
		t.Fatalf("MarshalRegistry: %v", err)
	}

	f, client := newSubmitFake(t, "testuser", upstream, http.StatusOK)
	_, err = submitRegistry(context.Background(), client, base, base, "Registry update")
	if !errors.Is(err, errRegistryChanged) {
		t.Fatalf("err = %v, want errRegistryChanged", err)
	}
	upstreamOnly(t, f)
}

func TestSubmitRegistry_EmptyBase_Refuses(t *testing.T) {
	reg := core.Registry{Keys: []core.KeyEntry{testKeyEntry(t, "Key X", nil)}}
	upstream, err := MarshalRegistry(reg)
	if err != nil {
		t.Fatalf("MarshalRegistry: %v", err)
	}

	f, client := newSubmitFake(t, "testuser", upstream, http.StatusOK)
	_, err = submitRegistry(context.Background(), client, nil, upstream, "Registry update")
	if !errors.Is(err, errRegistryChanged) {
		t.Fatalf("err = %v, want errRegistryChanged", err)
	}
	upstreamOnly(t, f)
}

func TestSubmitRegistry_UpstreamErrors(t *testing.T) {
	reg := core.Registry{Keys: []core.KeyEntry{testKeyEntry(t, "Key X", nil)}}
	base, err := MarshalRegistry(reg)
	if err != nil {
		t.Fatalf("MarshalRegistry: %v", err)
	}
	tests := []struct {
		name     string
		upstream []byte
		status   int
		wantMsg  string
	}{
		{"fetch fails", nil, http.StatusInternalServerError, "fetching upstream registry"},
		{"invalid registry", []byte(`{"keys":"nope"}`), http.StatusOK, "validating upstream registry"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, client := newSubmitFake(t, "testuser", tc.upstream, tc.status)
			_, err := submitRegistry(context.Background(), client, base, base, "Registry update")
			if err == nil || !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantMsg)
			}
			if errors.Is(err, errRegistryChanged) {
				t.Error("upstream failure must not be reported as errRegistryChanged")
			}
			upstreamOnly(t, f)
		})
	}
}

func TestFetchRegistry_LoggedInReadsMainViaAPI(t *testing.T) {
	to := "2027-12-31"
	reg := core.Registry{Keys: []core.KeyEntry{testKeyEntry(t, "Key X", &to)}}
	up, err := MarshalRegistry(reg)
	if err != nil {
		t.Fatalf("MarshalRegistry: %v", err)
	}
	f, client := newSubmitFake(t, "testuser", up, http.StatusOK)

	got, err := fetchRegistry(client)
	if err != nil {
		t.Fatalf("fetchRegistry: %v", err)
	}
	if len(got.Keys) != 1 || got.Keys[0].Authority != "Key X" {
		t.Errorf("got %+v, want the upstream registry", got.Keys)
	}
	if len(f.hits) != 1 || !strings.Contains(f.hits[0], "/contents/"+ghapi.RegistryFilePath) {
		t.Errorf("hits = %v, want one upstream contents GET", f.hits)
	}
}

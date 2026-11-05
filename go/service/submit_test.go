package service

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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

// revocationsPath is ghapi's revocation list path in the repository.
const revocationsPath = "verify/keys/revocations.json"

// submitFake is an httptest GitHub API covering the upstream registry and
// revocation list reads, the open-PR listing and the same-repo PR flow. It
// records every "METHOD path" it serves. Set the optional fields before the
// first request.
type submitFake struct {
	mu   sync.Mutex
	hits []string

	revocations       string // upstream revocations.json; "" = an empty list
	revocationsStatus int    // != 0 and != 200 makes the revocation list GET fail
	openPulls         string // GET pulls body; "" = no open PRs
	prURL             string // created PR's html_url; "" = a github.com URL
}

func (f *submitFake) hitList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.hits...)
}

// newSubmitFake starts the fake. upstream is served as the upstream main
// registry.json; upstreamStatus != 200 makes that GET fail instead.
func newSubmitFake(t *testing.T, upstream []byte, upstreamStatus int) (*submitFake, *ghapi.Client) {
	t.Helper()
	owner, repo := ghapi.DefaultOwner, ghapi.DefaultRepo
	repoPath := fmt.Sprintf("/repos/%s/%s", owner, repo)
	upstreamPath := repoPath + "/contents/" + ghapi.RegistryFilePath
	revPath := repoPath + "/contents/" + revocationsPath
	f := &submitFake{}
	serveFile := func(w http.ResponseWriter, content []byte) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"content":  base64.StdEncoding.EncodeToString(content),
			"encoding": "base64",
			"sha":      "upstreamsha123",
		})
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, method := r.URL.Path, r.Method
		f.mu.Lock()
		f.hits = append(f.hits, method+" "+path)
		revocations, revStatus, openPulls, prURL := f.revocations, f.revocationsStatus, f.openPulls, f.prURL
		f.mu.Unlock()

		switch {
		// The upstream read is on main; the PR flow's blob-SHA lookup is on
		// the new branch (same path, different ref).
		case method == http.MethodGet && path == upstreamPath && r.URL.Query().Get("ref") == "main":
			if upstreamStatus != http.StatusOK {
				w.WriteHeader(upstreamStatus)
				fmt.Fprint(w, `{"message":"boom"}`)
				return
			}
			serveFile(w, upstream)
		case method == http.MethodGet && path == revPath && r.URL.Query().Get("ref") == "main":
			if revStatus != 0 && revStatus != http.StatusOK {
				w.WriteHeader(revStatus)
				fmt.Fprint(w, `{"message":"boom"}`)
				return
			}
			if revocations == "" {
				revocations = `{"revocations":[]}`
			}
			serveFile(w, []byte(revocations))
		case method == http.MethodGet && path == repoPath+"/pulls":
			if openPulls == "" {
				openPulls = "[]"
			}
			fmt.Fprint(w, openPulls)
		case method == http.MethodGet && path == repoPath:
			fmt.Fprint(w, `{"permissions":{"push":true}}`)
		case method == http.MethodGet && path == repoPath+"/git/refs/heads/main":
			fmt.Fprint(w, `{"object":{"sha":"abc123deadbeef"}}`)
		case method == http.MethodPost && path == repoPath+"/git/refs":
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"ref":"refs/heads/registry-update-branch"}`)
		case method == http.MethodGet && strings.HasPrefix(path, repoPath+"/contents/"):
			fmt.Fprint(w, `{"sha":"existingfilesha456"}`)
		case method == http.MethodPut && strings.HasPrefix(path, repoPath+"/contents/"):
			fmt.Fprint(w, `{"content":{"sha":"newfilesha789"}}`)
		case method == http.MethodPost && path == fmt.Sprintf("/repos/%s/%s/pulls", owner, repo):
			if prURL == "" {
				prURL = fmt.Sprintf("https://github.com/%s/%s/pull/7", owner, repo)
			}
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"number":7,"html_url":%q}`, prURL)
		default:
			t.Errorf("unexpected request: %s %s", method, path)
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	client := ghapi.NewClient("test-token")
	client.HTTPClient = srv.Client()
	client.HTTPClient.Transport = &rewriteTransport{base: srv.Client().Transport, targetURL: srv.URL}
	return f, client
}

// upstreamOnly asserts the fake saw exactly the upstream registry GET — no
// repo, ref, PUT or pulls call.
func upstreamOnly(t *testing.T, f *submitFake) {
	t.Helper()
	want := fmt.Sprintf("GET /repos/%s/%s/contents/%s", ghapi.DefaultOwner, ghapi.DefaultRepo, ghapi.RegistryFilePath)
	hits := f.hitList()
	if len(hits) != 1 || hits[0] != want {
		t.Errorf("hits = %v, want only [%s]", hits, want)
	}
}

func TestSubmitIfUnchanged_UpstreamUnchanged_CreatesPR(t *testing.T) {
	to := "2027-12-31"
	reg := core.Registry{Keys: []core.KeyEntry{testKeyEntry(t, "Key X", &to), testKeyEntry(t, "Key Y", nil)}}
	base, err := marshalRegistry(reg)
	if err != nil {
		t.Fatalf("marshalRegistry: %v", err)
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
	content, err := marshalRegistry(edited)
	if err != nil {
		t.Fatalf("marshalRegistry: %v", err)
	}

	f, client := newSubmitFake(t, upstream, http.StatusOK)
	pr, err := submitIfUnchanged(context.Background(), client, base, content, "Registry update")
	if err != nil {
		t.Fatalf("submitIfUnchanged: %v", err)
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

func TestSubmitIfUnchanged_UpstreamChanged_Refuses(t *testing.T) {
	reg := core.Registry{Keys: []core.KeyEntry{testKeyEntry(t, "Key X", nil), testKeyEntry(t, "Key Y", nil)}}
	base, err := marshalRegistry(reg)
	if err != nil {
		t.Fatalf("marshalRegistry: %v", err)
	}
	// Another PR merged since the fetch and revoked key X.
	revoked := "2026-09-30"
	merged := reg
	merged.Keys = append([]core.KeyEntry(nil), reg.Keys...)
	merged.Keys[0].To = &revoked
	upstream, err := marshalRegistry(merged)
	if err != nil {
		t.Fatalf("marshalRegistry: %v", err)
	}

	f, client := newSubmitFake(t, upstream, http.StatusOK)
	_, err = submitIfUnchanged(context.Background(), client, base, base, "Registry update")
	if !errors.Is(err, ErrRegistryChanged) {
		t.Fatalf("err = %v, want ErrRegistryChanged", err)
	}
	upstreamOnly(t, f)
}

func TestSubmitIfUnchanged_EmptyBase_Refuses(t *testing.T) {
	reg := core.Registry{Keys: []core.KeyEntry{testKeyEntry(t, "Key X", nil)}}
	upstream, err := marshalRegistry(reg)
	if err != nil {
		t.Fatalf("marshalRegistry: %v", err)
	}

	f, client := newSubmitFake(t, upstream, http.StatusOK)
	_, err = submitIfUnchanged(context.Background(), client, nil, upstream, "Registry update")
	if !errors.Is(err, ErrRegistryChanged) {
		t.Fatalf("err = %v, want ErrRegistryChanged", err)
	}
	upstreamOnly(t, f)
}

func TestSubmitIfUnchanged_UpstreamErrors(t *testing.T) {
	reg := core.Registry{Keys: []core.KeyEntry{testKeyEntry(t, "Key X", nil)}}
	base, err := marshalRegistry(reg)
	if err != nil {
		t.Fatalf("marshalRegistry: %v", err)
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
			f, client := newSubmitFake(t, tc.upstream, tc.status)
			_, err := submitIfUnchanged(context.Background(), client, base, base, "Registry update")
			if err == nil || !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantMsg)
			}
			if errors.Is(err, ErrRegistryChanged) {
				t.Error("upstream failure must not be reported as ErrRegistryChanged")
			}
			upstreamOnly(t, f)
		})
	}
}

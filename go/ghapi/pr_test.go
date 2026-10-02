package ghapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

const testRepoPath = "/repos/" + DefaultOwner + "/" + DefaultRepo

// prFake is a fake GitHub API for the same-repo PR flow (createRepoFilePR).
// Every response is configurable; zero values give the happy path.
type prFake struct {
	mu sync.Mutex

	// Configuration (set before the first request).
	repoStatus      int      // GET /repos/{o}/{r}; 0 → 200
	repoBody        string   // "" → push permission granted
	refStatus       int      // GET git/refs/heads/main; 0 → 200
	createRefStatus []int    // per attempt; missing → 201
	createRefBody   string   // body for non-2xx createRef responses
	contentsStatus  []int    // per contents GET; missing → 200
	contentsSHAs    []string // per contents GET; missing → "file-sha-0"
	putStatus       []int    // per PUT; missing → 200
	prStatus        int      // POST pulls; 0 → 201
	deleteStatus    int      // DELETE git/refs/...; 0 → 204
	onPR            func()   // called before the PR response is written

	// Recorded.
	steps        []string            // logical step names in order
	createdRefs  []string            // "ref" field of each createRef POST
	createRefSHA string              // "sha" field of the last createRef POST
	contentsRefs []string            // "ref" query of each contents GET
	puts         []map[string]string // decoded PUT bodies
	prReq        map[string]string   // PR POST body
	deletedPaths []string            // DELETE paths
}

func (f *prFake) record(step string) int {
	f.steps = append(f.steps, step)
	n := 0
	for _, s := range f.steps {
		if s == step {
			n++
		}
	}
	return n - 1 // zero-based attempt index for this step
}

func statusAt(statuses []int, i, def int) int {
	if i < len(statuses) && statuses[i] != 0 {
		return statuses[i]
	}
	return def
}

func (f *prFake) stepList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.steps...)
}

func decodeBody(t *testing.T, r *http.Request) map[string]string {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Errorf("reading request body: %v", err)
	}
	var m map[string]string
	if err := json.Unmarshal(body, &m); err != nil {
		t.Errorf("decoding request body %q: %v", body, err)
	}
	return m
}

// newPRFake starts a fake server and returns it with a client routed to it.
// Requests outside DefaultOwner/DefaultRepo fail the test.
func newPRFake(t *testing.T, f *prFake) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		p := r.URL.Path
		switch {
		case r.Method == http.MethodGet && p == testRepoPath:
			f.record("repoAccess")
			body := f.repoBody
			if body == "" {
				body = `{"full_name": "` + DefaultOwner + `/` + DefaultRepo + `", "permissions": {"admin": false, "push": true, "pull": true}}`
			}
			w.WriteHeader(cmpOr(f.repoStatus, 200))
			w.Write([]byte(body))

		case r.Method == http.MethodGet && p == testRepoPath+"/git/refs/heads/main":
			f.record("getRef")
			w.WriteHeader(cmpOr(f.refStatus, 200))
			json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": "main-sha-000"}})

		case r.Method == http.MethodPost && p == testRepoPath+"/git/refs":
			i := f.record("createRef")
			req := decodeBody(t, r)
			f.createdRefs = append(f.createdRefs, req["ref"])
			f.createRefSHA = req["sha"]
			st := statusAt(f.createRefStatus, i, 201)
			w.WriteHeader(st)
			if st >= 300 && f.createRefBody != "" {
				w.Write([]byte(f.createRefBody))
			} else {
				w.Write([]byte(`{}`))
			}

		case r.Method == http.MethodGet && strings.HasPrefix(p, testRepoPath+"/contents/"):
			i := f.record("getContents")
			f.contentsRefs = append(f.contentsRefs, r.URL.Query().Get("ref"))
			st := statusAt(f.contentsStatus, i, 200)
			w.WriteHeader(st)
			sha := "file-sha-0"
			if i < len(f.contentsSHAs) {
				sha = f.contentsSHAs[i]
			}
			json.NewEncoder(w).Encode(map[string]string{"sha": sha})

		case r.Method == http.MethodPut && strings.HasPrefix(p, testRepoPath+"/contents/"):
			i := f.record("updateContents")
			req := decodeBody(t, r)
			req["path"] = strings.TrimPrefix(p, testRepoPath+"/contents/")
			f.puts = append(f.puts, req)
			w.WriteHeader(statusAt(f.putStatus, i, 200))
			w.Write([]byte(`{}`))

		case r.Method == http.MethodPost && p == testRepoPath+"/pulls":
			f.record("createPR")
			f.prReq = decodeBody(t, r)
			if f.onPR != nil {
				f.onPR()
			}
			st := cmpOr(f.prStatus, 201)
			w.WriteHeader(st)
			if st >= 300 {
				w.Write([]byte(`{"message": "Bad Gateway"}`))
				return
			}
			json.NewEncoder(w).Encode(PRResult{Number: 42, HTMLURL: "https://github.com/test/pr/42"})

		case r.Method == http.MethodDelete && strings.HasPrefix(p, testRepoPath+"/git/refs/"):
			f.record("deleteRef")
			f.deletedPaths = append(f.deletedPaths, p)
			w.WriteHeader(cmpOr(f.deleteStatus, 204))

		default:
			t.Errorf("unexpected request: %s %s", r.Method, p)
			w.WriteHeader(500)
		}
	}))
	t.Cleanup(srv.Close)
	return newTestClient(srv, "tok")
}

func cmpOr(v, def int) int {
	if v != 0 {
		return v
	}
	return def
}

// captureLog redirects the standard logger into a buffer for the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(orig) })
	return &buf
}

func runRepoFilePR(c *Client) (PRResult, error) {
	return c.createRepoFilePR(context.Background(), "path/file.json", []byte("new-content"), "prefix-", "the title", "the body")
}

func assertSteps(t *testing.T, f *prFake, want ...string) {
	t.Helper()
	if got := f.stepList(); !slices.Equal(got, want) {
		t.Errorf("steps = %v, want %v", got, want)
	}
}

// --- createRepoFilePR: happy path ---

func TestCreateRepoFilePR_Success(t *testing.T) {
	f := &prFake{}
	c := newPRFake(t, f)

	pr, err := runRepoFilePR(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pr.Number != 42 || pr.HTMLURL != "https://github.com/test/pr/42" {
		t.Errorf("PR = %+v, want #42", pr)
	}
	assertSteps(t, f, "repoAccess", "getRef", "createRef", "getContents", "updateContents", "createPR")

	if f.createRefSHA != "main-sha-000" {
		t.Errorf("createRef sha = %q, want main-sha-000", f.createRefSHA)
	}
	if len(f.createdRefs) != 1 || !strings.HasPrefix(f.createdRefs[0], "refs/heads/prefix-") {
		t.Fatalf("created refs = %v, want one refs/heads/prefix-*", f.createdRefs)
	}
	branch := strings.TrimPrefix(f.createdRefs[0], "refs/heads/")

	// Blob SHA is read from the new branch.
	if !slices.Equal(f.contentsRefs, []string{branch}) {
		t.Errorf("contents GET refs = %v, want [%s]", f.contentsRefs, branch)
	}

	put := f.puts[0]
	if put["path"] != "path/file.json" {
		t.Errorf("PUT path = %q, want path/file.json", put["path"])
	}
	if put["branch"] != branch {
		t.Errorf("PUT branch = %q, want %q", put["branch"], branch)
	}
	if put["sha"] != "file-sha-0" {
		t.Errorf("PUT sha = %q, want file-sha-0", put["sha"])
	}
	if put["message"] != "the title" {
		t.Errorf("PUT message = %q, want the title", put["message"])
	}
	if dec, _ := base64.StdEncoding.DecodeString(put["content"]); string(dec) != "new-content" {
		t.Errorf("PUT content = %q, want new-content", dec)
	}

	// Same-repo PR: head is the bare branch name (no "owner:" prefix).
	want := map[string]string{"head": branch, "base": "main", "title": "the title", "body": "the body"}
	for k, v := range want {
		if f.prReq[k] != v {
			t.Errorf("PR %s = %q, want %q", k, f.prReq[k], v)
		}
	}
	if strings.Contains(f.prReq["head"], ":") {
		t.Errorf("PR head = %q, want no owner prefix", f.prReq["head"])
	}
	if c.Owner != DefaultOwner || c.Repo != DefaultRepo {
		t.Errorf("client repo changed to %s/%s", c.Owner, c.Repo)
	}
}

// --- createRepoFilePR: write-access check ---

func TestCreateRepoFilePR_NoPushPermission(t *testing.T) {
	f := &prFake{repoBody: `{"permissions": {"admin": false, "push": false, "pull": true}}`}
	c := newPRFake(t, f)

	_, err := runRepoFilePR(c)
	if !errors.Is(err, ErrNoWriteAccess) {
		t.Fatalf("error = %v, want ErrNoWriteAccess", err)
	}
	assertSteps(t, f, "repoAccess")
}

func TestCreateRepoFilePR_PermissionsAbsent_Proceeds(t *testing.T) {
	f := &prFake{repoBody: `{"full_name": "RoyalHouseOfGeorgia/rhg_authenticator"}`}
	c := newPRFake(t, f)

	if _, err := runRepoFilePR(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertSteps(t, f, "repoAccess", "getRef", "createRef", "getContents", "updateContents", "createPR")
}

func TestCreateRepoFilePR_PermissionsNull_Proceeds(t *testing.T) {
	f := &prFake{repoBody: `{"permissions": null}`}
	c := newPRFake(t, f)

	if _, err := runRepoFilePR(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCreateRepoFilePR_RepoCheckFails(t *testing.T) {
	f := &prFake{repoStatus: 500, repoBody: `{"message": "boom"}`}
	c := newPRFake(t, f)

	_, err := runRepoFilePR(c)
	if err == nil {
		t.Fatal("expected error")
	}
	if errors.Is(err, ErrNoWriteAccess) {
		t.Errorf("error = %v, must not be ErrNoWriteAccess", err)
	}
	if !strings.Contains(err.Error(), "checking repository access") {
		t.Errorf("error = %q, want 'checking repository access'", err.Error())
	}
	var ae *APIError
	if !errors.As(err, &ae) || ae.StatusCode != 500 {
		t.Errorf("error = %v, want wrapped 500 APIError", err)
	}
	assertSteps(t, f, "repoAccess")
}

func TestCreateRepoFilePR_RepoCheckForbidden(t *testing.T) {
	// A 403 on the access check keeps its APIError so UserMessage reports it
	// as a permission problem.
	f := &prFake{repoStatus: 403, repoBody: `{"message": "Resource not accessible"}`}
	c := newPRFake(t, f)

	_, err := runRepoFilePR(c)
	if !IsForbidden(err) {
		t.Fatalf("error = %v, want wrapped 403", err)
	}
	if errors.Is(err, ErrNoWriteAccess) {
		t.Errorf("error = %v, must not be ErrNoWriteAccess", err)
	}
	assertSteps(t, f, "repoAccess")
}

// --- createRepoFilePR: failures before the branch exists (no cleanup) ---

func TestCreateRepoFilePR_GetRefFails(t *testing.T) {
	f := &prFake{refStatus: 404}
	c := newPRFake(t, f)

	_, err := runRepoFilePR(c)
	if err == nil || !strings.Contains(err.Error(), "getting main ref") {
		t.Fatalf("error = %v, want 'getting main ref'", err)
	}
	assertSteps(t, f, "repoAccess", "getRef")
}

func TestCreateRepoFilePR_BranchCollision422_Retries(t *testing.T) {
	f := &prFake{createRefStatus: []int{422}, createRefBody: `{"message": "Reference already exists"}`}
	c := newPRFake(t, f)

	if _, err := runRepoFilePR(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(f.createdRefs) != 2 {
		t.Fatalf("createRef attempts = %d, want 2", len(f.createdRefs))
	}
	if f.createdRefs[0] == f.createdRefs[1] {
		t.Errorf("retry reused branch name %q", f.createdRefs[0])
	}
	// The PR uses the branch that was actually created.
	if want := strings.TrimPrefix(f.createdRefs[1], "refs/heads/"); f.prReq["head"] != want {
		t.Errorf("PR head = %q, want %q", f.prReq["head"], want)
	}
	if slices.Contains(f.stepList(), "deleteRef") {
		t.Error("unexpected cleanup after successful retry")
	}
}

func TestCreateRepoFilePR_BranchCollision422_Exhausted(t *testing.T) {
	// Any 422 message triggers a retry, not just "Reference already exists".
	f := &prFake{createRefStatus: []int{422, 422, 422}, createRefBody: `{"message": "Validation Failed"}`}
	c := newPRFake(t, f)

	_, err := runRepoFilePR(c)
	if err == nil || !strings.Contains(err.Error(), "branch name collision") {
		t.Fatalf("error = %v, want 'branch name collision'", err)
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("%d", maxBranchRetries)) {
		t.Errorf("error = %q, want retry count", err.Error())
	}
	if len(f.createdRefs) != maxBranchRetries {
		t.Errorf("createRef attempts = %d, want %d", len(f.createdRefs), maxBranchRetries)
	}
	if slices.Contains(f.stepList(), "deleteRef") {
		t.Error("cleanup must not run when no branch was created")
	}
}

func TestCreateRepoFilePR_CreateBranchNon422Fails(t *testing.T) {
	f := &prFake{createRefStatus: []int{403}, createRefBody: `{"message": "Forbidden"}`}
	c := newPRFake(t, f)

	_, err := runRepoFilePR(c)
	if err == nil || !strings.Contains(err.Error(), "creating branch") {
		t.Fatalf("error = %v, want 'creating branch'", err)
	}
	if !IsForbidden(err) {
		t.Errorf("error = %v, want wrapped 403", err)
	}
	assertSteps(t, f, "repoAccess", "getRef", "createRef")
}

// --- createRepoFilePR: failures after the branch exists (cleanup) ---

// assertCleanedUp checks that exactly the created branch was deleted.
func assertCleanedUp(t *testing.T, f *prFake) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.createdRefs) == 0 {
		t.Fatal("no branch was created")
	}
	want := testRepoPath + "/git/" + f.createdRefs[len(f.createdRefs)-1]
	if !slices.Equal(f.deletedPaths, []string{want}) {
		t.Errorf("DELETE paths = %v, want [%s]", f.deletedPaths, want)
	}
}

func TestCreateRepoFilePR_GetContentsFails_Cleanup(t *testing.T) {
	f := &prFake{contentsStatus: []int{429}}
	c := newPRFake(t, f)

	_, err := runRepoFilePR(c)
	if err == nil || !strings.Contains(err.Error(), "getting file SHA") {
		t.Fatalf("error = %v, want 'getting file SHA'", err)
	}
	if !IsRateLimited(err) {
		t.Errorf("error = %v, want wrapped 429", err)
	}
	assertSteps(t, f, "repoAccess", "getRef", "createRef", "getContents", "deleteRef")
	assertCleanedUp(t, f)
}

func TestCreateRepoFilePR_UpdateContentsFails_Cleanup(t *testing.T) {
	f := &prFake{putStatus: []int{500}}
	c := newPRFake(t, f)

	_, err := runRepoFilePR(c)
	if err == nil || !strings.Contains(err.Error(), "updating file") {
		t.Fatalf("error = %v, want 'updating file'", err)
	}
	// Non-409 errors are not retried.
	assertSteps(t, f, "repoAccess", "getRef", "createRef", "getContents", "updateContents", "deleteRef")
	assertCleanedUp(t, f)
}

func TestCreateRepoFilePR_StaleFileSHA409_Retries(t *testing.T) {
	f := &prFake{putStatus: []int{409}, contentsSHAs: []string{"old-sha", "new-sha"}}
	c := newPRFake(t, f)

	if _, err := runRepoFilePR(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertSteps(t, f, "repoAccess", "getRef", "createRef", "getContents", "updateContents", "getContents", "updateContents", "createPR")
	if f.puts[0]["sha"] != "old-sha" || f.puts[1]["sha"] != "new-sha" {
		t.Errorf("PUT shas = %q, %q; want old-sha, new-sha", f.puts[0]["sha"], f.puts[1]["sha"])
	}
	// Both SHA lookups read the PR branch.
	branch := strings.TrimPrefix(f.createdRefs[0], "refs/heads/")
	if !slices.Equal(f.contentsRefs, []string{branch, branch}) {
		t.Errorf("contents GET refs = %v, want both %q", f.contentsRefs, branch)
	}
}

func TestCreateRepoFilePR_StaleFileSHA409_RetryFails_Cleanup(t *testing.T) {
	f := &prFake{putStatus: []int{409, 409}}
	c := newPRFake(t, f)

	_, err := runRepoFilePR(c)
	if err == nil || !strings.Contains(err.Error(), "updating file (retry)") {
		t.Fatalf("error = %v, want 'updating file (retry)'", err)
	}
	assertCleanedUp(t, f)
}

func TestCreateRepoFilePR_StaleFileSHA409_RefetchFails_Cleanup(t *testing.T) {
	f := &prFake{putStatus: []int{409}, contentsStatus: []int{200, 500}}
	c := newPRFake(t, f)

	_, err := runRepoFilePR(c)
	if err == nil || !strings.Contains(err.Error(), "re-fetching file SHA after 409") {
		t.Fatalf("error = %v, want 're-fetching file SHA after 409'", err)
	}
	assertCleanedUp(t, f)
}

func TestCreateRepoFilePR_CreatePRFails_Cleanup(t *testing.T) {
	f := &prFake{prStatus: 502}
	c := newPRFake(t, f)

	_, err := runRepoFilePR(c)
	if err == nil || !strings.Contains(err.Error(), "creating pull request") {
		t.Fatalf("error = %v, want 'creating pull request'", err)
	}
	var ae *APIError
	if !errors.As(err, &ae) || ae.StatusCode != 502 {
		t.Errorf("error = %v, want wrapped 502", err)
	}
	assertSteps(t, f, "repoAccess", "getRef", "createRef", "getContents", "updateContents", "createPR", "deleteRef")
	assertCleanedUp(t, f)
}

func TestCreateRepoFilePR_CleanupFailureLoggedNotFatal(t *testing.T) {
	logs := captureLog(t)
	f := &prFake{prStatus: 502, deleteStatus: 500}
	c := newPRFake(t, f)

	_, err := runRepoFilePR(c)
	if err == nil {
		t.Fatal("expected error")
	}
	// The caller sees the PR failure, not the cleanup failure.
	var ae *APIError
	if !errors.As(err, &ae) || ae.StatusCode != 502 {
		t.Errorf("error = %v, want wrapped 502 from createPR", err)
	}
	assertCleanedUp(t, f)
	branch := strings.TrimPrefix(f.createdRefs[0], "refs/heads/")
	if out := logs.String(); !strings.Contains(out, "failed to clean up branch "+branch) {
		t.Errorf("log = %q, want cleanup warning for %s", out, branch)
	}
}

func TestCreateRepoFilePR_CleanupSurvivesCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Cancel the caller's context while the PR request is in flight; cleanup
	// must still run on its own context.
	f := &prFake{prStatus: 502, onPR: cancel}
	c := newPRFake(t, f)

	_, err := c.createRepoFilePR(ctx, "path/file.json", []byte("x"), "prefix-", "t", "b")
	if err == nil {
		t.Fatal("expected error")
	}
	assertCleanedUp(t, f)
}

// --- CreateRegistryPR wiring ---

func TestCreateRegistryPR_UsesRegistryPathAndPrefix(t *testing.T) {
	reg := core.Registry{Keys: []core.KeyEntry{{
		Authority: "Test Authority",
		From:      "2025-01-01",
		Algorithm: "Ed25519",
		PublicKey: "/PjT+j342wWZypb0m/4MSBsFhHrrqzpoTe2rZ9hf0XU=",
		Note:      "Test key",
	}}}
	content, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	content = append(content, '\n')

	f := &prFake{}
	c := newPRFake(t, f)
	pr, err := c.CreateRegistryPR(context.Background(), content, "Update registry")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pr.Number != 42 {
		t.Errorf("PR number = %d, want 42", pr.Number)
	}
	if f.puts[0]["path"] != RegistryFilePath {
		t.Errorf("PUT path = %q, want %q", f.puts[0]["path"], RegistryFilePath)
	}
	if !strings.HasPrefix(f.prReq["head"], "registry-update-") {
		t.Errorf("PR head = %q, want prefix registry-update-", f.prReq["head"])
	}
	if f.prReq["title"] != "Update registry" || f.prReq["body"] != "Registry update submitted via RHG Authenticator" {
		t.Errorf("PR title/body = %q / %q", f.prReq["title"], f.prReq["body"])
	}

	// Content round-trips through base64 as a valid registry.
	decoded, err := base64.StdEncoding.DecodeString(f.puts[0]["content"])
	if err != nil {
		t.Fatalf("PUT content not base64: %v", err)
	}
	got, err := core.ValidateRegistry(decoded)
	if err != nil {
		t.Fatalf("PUT content is not a valid registry: %v", err)
	}
	if len(got.Keys) != 1 || got.Keys[0].Authority != "Test Authority" {
		t.Errorf("round-tripped keys = %+v", got.Keys)
	}
}

func TestCreateRegistryPR_NoWriteAccess(t *testing.T) {
	f := &prFake{repoBody: `{"permissions": {"push": false}}`}
	c := newPRFake(t, f)

	_, err := c.CreateRegistryPR(context.Background(), []byte("content"), "title")
	if !errors.Is(err, ErrNoWriteAccess) {
		t.Fatalf("error = %v, want ErrNoWriteAccess", err)
	}
	if got := UserMessage(err); !strings.Contains(got, "collaborator") {
		t.Errorf("UserMessage = %q, want collaborator guidance", got)
	}
	assertSteps(t, f, "repoAccess")
}

// --- Low-level helpers target c.Owner/c.Repo ---

func TestHelpers_UseClientOwnerRepo(t *testing.T) {
	var paths []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			w.Write([]byte(`{"sha": "s", "object": {"sha": "s"}}`))
		case http.MethodPost:
			w.WriteHeader(201)
			w.Write([]byte(`{"number": 1}`))
		case http.MethodDelete:
			w.WriteHeader(204)
		default:
			w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	c.Owner, c.Repo = "custom-owner", "custom-repo"
	ctx := context.Background()
	if _, err := c.getRef(ctx, "heads/main"); err != nil {
		t.Fatal(err)
	}
	if err := c.createRef(ctx, "heads/b", "sha"); err != nil {
		t.Fatal(err)
	}
	if err := c.deleteRef(ctx, "heads/b"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.getContents(ctx, "f.json", "b"); err != nil {
		t.Fatal(err)
	}
	if err := c.updateContents(ctx, "f.json", "b", []byte("x"), "sha", "msg"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.createPR(ctx, "b", "main", "t", "body"); err != nil {
		t.Fatal(err)
	}

	base := "/repos/custom-owner/custom-repo"
	want := []string{
		"GET " + base + "/git/refs/heads/main",
		"POST " + base + "/git/refs",
		"DELETE " + base + "/git/refs/heads/b",
		"GET " + base + "/contents/f.json",
		"PUT " + base + "/contents/f.json",
		"POST " + base + "/pulls",
	}
	if !slices.Equal(paths, want) {
		t.Errorf("paths =\n%v\nwant\n%v", paths, want)
	}
}

func TestUpdateContentsWithRetry_Non409NotRetried(t *testing.T) {
	var puts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		puts++
		w.WriteHeader(422)
		w.Write([]byte(`{"message": "Invalid request"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	err := c.updateContentsWithRetry(context.Background(), "f.json", "b", []byte("x"), "sha", "msg")
	if err == nil || !strings.Contains(err.Error(), "updating file") {
		t.Fatalf("error = %v, want 'updating file'", err)
	}
	if puts != 1 {
		t.Errorf("requests = %d, want 1", puts)
	}
}

func TestUpdateContentsWithRetry_NonAPIErrorNotRetried(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // connection refused → non-APIError

	c := newTestClient(srv, "tok")
	err := c.updateContentsWithRetry(context.Background(), "f.json", "b", []byte("x"), "sha", "msg")
	if err == nil || !strings.Contains(err.Error(), "updating file:") {
		t.Fatalf("error = %v, want 'updating file:'", err)
	}
	var ae *APIError
	if errors.As(err, &ae) {
		t.Errorf("error = %v, want a transport error", err)
	}
}

// --- findOpenRevocationPR ---

func TestFindOpenRevocationPR(t *testing.T) {
	ref := revocationBranchPrefix(testRevHashB) + "20261001T000000Z-abc"
	thisRepo := DefaultOwner + "/" + DefaultRepo
	pull := func(ref, repoJSON string) string {
		return `{"head": {"ref": "` + ref + `", "repo": ` + repoJSON + `}}`
	}
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"same-repo PR", `[` + pull(ref, `{"full_name": "`+thisRepo+`"}`) + `]`, true},
		{"same-repo PR, full_name case differs", `[` + pull(ref, `{"full_name": "`+strings.ToLower(thisRepo)+`"}`) + `]`, true},
		{"same-repo PR by any author", `[{"head": {"ref": "` + ref + `", "repo": {"full_name": "` + thisRepo + `"}, "user": {"login": "other-operator"}}}]`, true},
		{"fork PR with spoofed branch", `[` + pull(ref, `{"full_name": "attacker/`+DefaultRepo+`"}`) + `]`, false},
		{"fork PR named like upstream owner", `[` + pull(ref, `{"full_name": "`+DefaultOwner+`/other"}`) + `]`, false},
		{"head repo null (deleted fork)", `[` + pull(ref, `null`) + `]`, false},
		{"head repo absent", `[{"head": {"ref": "` + ref + `"}}]`, false},
		{"same repo, other hash", `[` + pull(revocationBranchPrefix(testRevHashA)+"x", `{"full_name": "`+thisRepo+`"}`) + `]`, false},
		{"same repo, non-revocation branch", `[` + pull("registry-update-x", `{"full_name": "`+thisRepo+`"}`) + `]`, false},
		{"match after non-matches", `[` + pull(ref, `null`) + `,` + pull(ref, `{"full_name": "`+thisRepo+`"}`) + `]`, true},
		{"no open PRs", `[]`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			c := newTestClient(srv, "tok")
			got, err := c.findOpenRevocationPR(context.Background(), testRevHashB)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("pending = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFindOpenRevocationPR_UsesClientRepo(t *testing.T) {
	ref := revocationBranchPrefix(testRevHashB) + "x"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/o/r/pulls" {
			t.Errorf("path = %s, want /repos/o/r/pulls", r.URL.Path)
		}
		w.Write([]byte(`[{"head": {"ref": "` + ref + `", "repo": {"full_name": "o/r"}}}]`))
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	c.Owner, c.Repo = "o", "r"
	got, err := c.findOpenRevocationPR(context.Background(), testRevHashB)
	if err != nil || !got {
		t.Errorf("pending, err = %v, %v; want true, nil", got, err)
	}
}

func TestFindOpenRevocationPR_ListFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte(`{"message": "boom"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv, "tok")
	_, err := c.findOpenRevocationPR(context.Background(), testRevHashB)
	if err == nil || !strings.Contains(err.Error(), "listing open pull requests") {
		t.Errorf("error = %v, want 'listing open pull requests'", err)
	}
}

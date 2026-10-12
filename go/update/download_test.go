package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

// useTLSServer starts an httptest TLS server running h and points
// downloadClient at a client that trusts it (keeping SafeRedirect).
func useTLSServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(h)
	client := server.Client()
	client.CheckRedirect = core.SafeRedirect
	orig := downloadClient
	downloadClient = client
	t.Cleanup(func() {
		downloadClient = orig
		server.Close()
	})
	return server
}

// setMaxDownload lowers maxDownloadBytes for the duration of the test.
func setMaxDownload(t *testing.T, n int64) {
	t.Helper()
	orig := maxDownloadBytes
	maxDownloadBytes = n
	t.Cleanup(func() { maxDownloadBytes = orig })
}

// assertNoLeftovers fails if dir contains any entry (e.g. a .partial file).
func assertNoLeftovers(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("unexpected leftover file %q", e.Name())
	}
}

func TestDownload_Success(t *testing.T) {
	payload := bytes.Repeat([]byte("rhg-zip-payload\x00\xff"), 4096)
	server := useTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	})
	dir := filepath.Join(t.TempDir(), "update")

	got, err := download(context.Background(), server.URL+"/a.zip", dir, "v1.5")
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if want := filepath.Join(dir, "1.5.0.zip"); got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
	data, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(data) != sha256.Sum256(payload) {
		t.Fatal("downloaded content hash mismatch")
	}
	if _, err := os.Stat(got + ".partial"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial file should be gone, stat err = %v", err)
	}
	fi, err := os.Stat(got)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("zip mode = %v, want no group/other access", perm)
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := di.Mode().Perm(); perm&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("dir mode = %v, want 0700", perm)
	}
}

func TestDownload_ExactlyAtCap(t *testing.T) {
	setMaxDownload(t, 1024)
	server := useTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 1024))
	})
	if _, err := download(context.Background(), server.URL, t.TempDir(), "v1.5.0"); err != nil {
		t.Fatalf("download at cap: %v", err)
	}
}

func TestDownload_OverwritesStalePartial(t *testing.T) {
	server := useTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("new"))
	})
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "1.5.0.zip.partial"), []byte("stale-and-longer"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := download(context.Background(), server.URL, dir, "1.5.0")
	if err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(got); string(data) != "new" {
		t.Fatalf("content = %q, want %q", data, "new")
	}
}

func TestDownload_Oversize(t *testing.T) {
	setMaxDownload(t, 1024)
	cases := []struct {
		name string
		h    http.HandlerFunc
	}{
		// Chunked (no Content-Length): caught while streaming.
		{"streamed", func(w http.ResponseWriter, r *http.Request) {
			w.Write(make([]byte, 600))
			w.(http.Flusher).Flush()
			w.Write(make([]byte, 600))
		}},
		// Declared Content-Length over the cap: rejected before writing.
		{"content-length", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(2048))
			w.Write(make([]byte, 2048))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := useTLSServer(t, tc.h)
			dir := t.TempDir()
			if _, err := download(context.Background(), server.URL, dir, "v1.5.0"); err == nil {
				t.Fatal("expected oversize error")
			}
			assertNoLeftovers(t, dir)
		})
	}
}

func TestDownload_HTTPErrors(t *testing.T) {
	for _, code := range []int{http.StatusNotFound, http.StatusInternalServerError} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			server := useTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "nope", code)
			})
			dir := t.TempDir()
			if _, err := download(context.Background(), server.URL, dir, "v1.5.0"); err == nil {
				t.Fatalf("expected error on HTTP %d", code)
			}
			assertNoLeftovers(t, dir)
		})
	}
}

func TestDownload_RejectsNonHTTPS(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer server.Close()

	for _, u := range []string{server.URL, "ftp://example.com/a.zip", "/a.zip", "https:///a.zip", "://bad", ""} {
		t.Run(u, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "update")
			if _, err := download(context.Background(), u, dir, "v1.5.0"); err == nil {
				t.Fatalf("expected rejection of %q", u)
			}
			assertNoLeftovers(t, dir)
		})
	}
	if called {
		t.Fatal("non-https URL must not be fetched")
	}
}

func TestDownload_RejectsHTTPRedirect(t *testing.T) {
	server := useTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/a.zip", http.StatusFound)
	})
	dir := t.TempDir()
	if _, err := download(context.Background(), server.URL, dir, "v1.5.0"); err == nil {
		t.Fatal("expected redirect to http to be rejected")
	}
	assertNoLeftovers(t, dir)
}

func TestDownload_InvalidVersion(t *testing.T) {
	for _, v := range []string{"", "dev", "../../x", "1.2.3/../../x"} {
		t.Run(v, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "update")
			if _, err := download(context.Background(), "https://example.com/a.zip", dir, v); err == nil {
				t.Fatalf("expected rejection of version %q", v)
			}
			assertNoLeftovers(t, dir)
		})
	}
}

func TestDownload_CanceledContext(t *testing.T) {
	server := useTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("x"))
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dir := t.TempDir()
	if _, err := download(ctx, server.URL, dir, "v1.5.0"); err == nil {
		t.Fatal("expected error with canceled context")
	}
	assertNoLeftovers(t, dir)
}

func TestDownload_BodyReadError(t *testing.T) {
	// Declared length longer than the body: the client sees an unexpected EOF.
	server := useTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.Write([]byte("short"))
	})
	dir := t.TempDir()
	if _, err := download(context.Background(), server.URL, dir, "v1.5.0"); err == nil {
		t.Fatal("expected error on truncated body")
	}
	assertNoLeftovers(t, dir)
}

func TestDownload_DestDirNotCreatable(t *testing.T) {
	parent := t.TempDir()
	blocker := filepath.Join(parent, "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := download(context.Background(), "https://example.com/a.zip", filepath.Join(blocker, "update"), "v1.5.0"); err == nil {
		t.Fatal("expected error when destDir cannot be created")
	}
}

func TestDownload_PartialNotCreatable(t *testing.T) {
	server := useTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("x"))
	})
	dir := t.TempDir()
	// A directory squatting on the partial path makes OpenFile fail.
	if err := os.Mkdir(filepath.Join(dir, "1.5.0.zip.partial"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := download(context.Background(), server.URL, dir, "v1.5.0"); err == nil {
		t.Fatal("expected error when partial file cannot be created")
	}
}

func TestDownload_RenameFails(t *testing.T) {
	server := useTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("x"))
	})
	dir := t.TempDir()
	// A non-empty directory at the final path makes the rename fail.
	if err := os.MkdirAll(filepath.Join(dir, "1.5.0.zip", "keep"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := download(context.Background(), server.URL, dir, "v1.5.0"); err == nil {
		t.Fatal("expected error when rename fails")
	}
	if _, err := os.Stat(filepath.Join(dir, "1.5.0.zip.partial")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial file should be removed, stat err = %v", err)
	}
}

func TestDownloadClient_Config(t *testing.T) {
	if downloadClient.Timeout != downloadTimeout || downloadTimeout <= checkTimeout {
		t.Fatalf("download timeout = %v, want %v (> check timeout)", downloadClient.Timeout, downloadTimeout)
	}
	if downloadClient.CheckRedirect == nil {
		t.Fatal("download client must reject non-https redirects")
	}
}

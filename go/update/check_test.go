package update

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// botRelease builds a release as the release workflow publishes it.
func botRelease(tag, htmlURL string) githubRelease {
	r := githubRelease{TagName: tag, HTMLURL: htmlURL}
	r.Author.Login = releaseAuthor
	return r
}

func TestCheck_UpdateAvailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(botRelease("v2.0.0", "https://github.com/example/releases/v2.0.0"))
	}))
	defer server.Close()

	result := checkInternal(server.URL, "v1.0.0", checkTimeout)
	if !result.UpdateAvailable {
		t.Fatal("expected update available")
	}
	if result.LatestVersion != "v2.0.0" {
		t.Fatalf("expected v2.0.0, got %s", result.LatestVersion)
	}
	if result.DownloadURL == "" {
		t.Fatal("expected download URL")
	}
}

func TestCheck_NotNewer(t *testing.T) {
	tests := []struct {
		name string
		tag  string
	}{
		{"SameVersion", "v1.0.0"},
		{"OlderVersion", "v0.9.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(botRelease(tt.tag, "https://example.com"))
			}))
			defer server.Close()

			result := checkInternal(server.URL, "v1.0.0", checkTimeout)
			if result.UpdateAvailable {
				t.Fatalf("expected no update when latest is %s", tt.tag)
			}
		})
	}
}

func TestCheck_Server404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	result := checkInternal(server.URL, "v1.0.0", checkTimeout)
	if result.UpdateAvailable {
		t.Fatal("expected no update on 404")
	}
}

func TestCheck_ServerTimeout(t *testing.T) {
	// Serves a real update after 1 s, so the test fails unless the 50 ms
	// client timeout fires first.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(time.Second):
		}
		json.NewEncoder(w).Encode(botRelease("v2.0.0", "https://example.com"))
	}))
	defer server.Close()

	result := checkInternal(server.URL, "v1.0.0", 50*time.Millisecond)
	if result.UpdateAvailable {
		t.Fatal("expected no update on timeout")
	}
}

func TestCheck_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	result := checkInternal(server.URL, "v1.0.0", checkTimeout)
	if result.UpdateAvailable {
		t.Fatal("expected no update on invalid JSON")
	}
}

// TestCheck_OnlyVTagsOfferUpdates: only maintainer-only v* tags may produce an
// update banner; a release on any other tag (which a collaborator could
// create) is ignored entirely.
func TestCheck_OnlyVTagsOfferUpdates(t *testing.T) {
	cases := []struct {
		tag  string
		want bool
	}{
		{"v9.9.0", true},
		{"v9.9.1", true},
		{"v9.9", false},
		{"9.9", false},
		{"9.9.0", false},
		{"V9.9", false},
		{"v9.9-rc1", false},
		{"v9.9.1.2", false},
		{"v9", false},
		{"release-v9.9", false},
		{"v9.9\n", false},
		{"v9.9.0\n", false},
		{"v9.9.0 ", false},
		{"v９.9.0", false},
	}
	for _, tc := range cases {
		t.Run(tc.tag, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(botRelease(tc.tag, "https://github.com/x/y/releases/tag/"+tc.tag))
			}))
			defer server.Close()

			result := checkInternal(server.URL, "v1.4", checkTimeout)
			if result.UpdateAvailable != tc.want {
				t.Errorf("tag %q: UpdateAvailable = %v, want %v", tc.tag, result.UpdateAvailable, tc.want)
			}
			if !tc.want && (result.LatestVersion != "" || result.DownloadURL != "") {
				t.Errorf("tag %q: rejected release must not populate LatestVersion/DownloadURL", tc.tag)
			}
		})
	}
}

// TestCheck_OnlyWorkflowReleasesOfferUpdates: a release created by hand on a
// v* tag (e.g. by a collaborator before the workflow publishes) is ignored.
func TestCheck_OnlyWorkflowReleasesOfferUpdates(t *testing.T) {
	for _, author := range []string{"", "some-collaborator", "github-actions"} {
		t.Run(author, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				rel := botRelease("v9.9.0", "https://github.com/x/y/releases/tag/v9.9.0")
				rel.Author.Login = author
				json.NewEncoder(w).Encode(rel)
			}))
			defer server.Close()

			result := checkInternal(server.URL, "v1.4", checkTimeout)
			if result.UpdateAvailable || result.DownloadURL != "" {
				t.Errorf("author %q: release must be ignored, got %+v", author, result)
			}
		})
	}
}

func TestCheck_ConnectionRefused(t *testing.T) {
	result := checkInternal("http://127.0.0.1:1", "v1.0.0", checkTimeout)
	if result.UpdateAvailable {
		t.Fatal("expected no update on connection error")
	}
}

func TestCheck_RejectsHTTPRedirect(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		json.NewEncoder(w).Encode(botRelease("v2.0.0", "https://example.com"))
	}))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer server.Close()

	result := checkInternal(server.URL, "v1.0.0", checkTimeout)
	if n := hits.Load(); n != 0 {
		t.Errorf("http redirect target fetched %d times, want 0", n)
	}
	if result.UpdateAvailable {
		t.Fatal("expected no update when redirect to HTTP is rejected")
	}
}

func TestCheck_OversizedResponse(t *testing.T) {
	// Server returns a response body larger than 1MB.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Write valid JSON prefix, then pad with spaces to exceed 1MB, then close the JSON.
		// The LimitReader should truncate the body, causing a JSON decode error.
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"tag_name":"v9.9.9","html_url":"https://example.com/release","padding":"`))
		w.Write([]byte(strings.Repeat("A", 2<<20))) // 2MB of padding
		w.Write([]byte(`"}`))
	}))
	defer server.Close()

	result := checkInternal(server.URL, "v1.0.0", checkTimeout)
	if result.UpdateAvailable {
		t.Fatal("expected no update when response exceeds 1MB limit")
	}
}

// assetServer serves a bot release for v9.9.0 with the given assets.
func assetServer(t *testing.T, assets []githubAsset) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rel := botRelease("v9.9.0", "https://github.com/x/y/releases/tag/v9.9.0")
		rel.Assets = assets
		json.NewEncoder(w).Encode(rel)
	}))
	t.Cleanup(server.Close)
	return server
}

// botAsset returns an asset uploaded by the release workflow.
func botAsset(name, url string) githubAsset {
	a := githubAsset{Name: name, BrowserDownloadURL: url}
	a.Uploader.Login = releaseAuthor
	return a
}

func TestCheck_AssetURL(t *testing.T) {
	const good = "https://github.com/x/y/releases/download/v9.9.0/" + darwinAssetName
	collab := botAsset(darwinAssetName, good)
	collab.Uploader.Login = "some-collaborator"
	cases := []struct {
		name   string
		assets []githubAsset
		want   string
	}{
		{"present", []githubAsset{
			botAsset("rhg-authenticator-windows-amd64.zip", "https://example.com/win.zip"),
			botAsset(darwinAssetName, good),
		}, good},
		{"uploaded by a collaborator", []githubAsset{collab}, ""},
		{"no uploader", []githubAsset{{Name: darwinAssetName, BrowserDownloadURL: good}}, ""},
		{"no assets", nil, ""},
		{"missing", []githubAsset{{Name: "other.zip", BrowserDownloadURL: "https://example.com/o.zip"}}, ""},
		{"name not exact", []githubAsset{{Name: darwinAssetName + ".sig", BrowserDownloadURL: "https://example.com/s"}}, ""},
		{"http", []githubAsset{botAsset(darwinAssetName, "http://example.com/a.zip")}, ""},
		{"relative", []githubAsset{botAsset(darwinAssetName, "/a.zip")}, ""},
		{"no host", []githubAsset{botAsset(darwinAssetName, "https:///a.zip")}, ""},
		{"empty", []githubAsset{botAsset(darwinAssetName, "")}, ""},
		{"unparsable", []githubAsset{botAsset(darwinAssetName, "https://exa mple.com/%zz")}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := assetServer(t, tc.assets)
			result := checkInternal(server.URL, "v1.0.0", checkTimeout)
			if !result.UpdateAvailable {
				t.Fatal("expected update available")
			}
			if result.AssetURL != tc.want {
				t.Errorf("AssetURL = %q, want %q", result.AssetURL, tc.want)
			}
			if result.DownloadURL != "https://github.com/x/y/releases/tag/v9.9.0" {
				t.Errorf("DownloadURL = %q, want release page", result.DownloadURL)
			}
		})
	}
}

// TestCheck_AssetsDecodedFromJSON exercises the real GitHub field names
// rather than round-tripping our own struct.
func TestCheck_AssetsDecodedFromJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"tag_name":"v9.9.0","html_url":"https://github.com/x/y/releases/tag/v9.9.0",` +
			`"author":{"login":"github-actions[bot]"},` +
			`"assets":[{"name":"rhg-authenticator-darwin-arm64.zip",` +
			`"browser_download_url":"https://github.com/x/y/releases/download/v9.9.0/rhg-authenticator-darwin-arm64.zip",` +
			`"uploader":{"login":"github-actions[bot]"}}]}`))
	}))
	defer server.Close()

	result := checkInternal(server.URL, "v1.0.0", checkTimeout)
	want := "https://github.com/x/y/releases/download/v9.9.0/rhg-authenticator-darwin-arm64.zip"
	if result.AssetURL != want {
		t.Fatalf("AssetURL = %q, want %q", result.AssetURL, want)
	}
}

// TestCheck_RejectedReleaseHasNoAssetURL: a release ignored for its tag or
// author must not leak an asset URL either.
func TestCheck_RejectedReleaseHasNoAssetURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rel := botRelease("v9.9.0", "https://github.com/x/y/releases/tag/v9.9.0")
		rel.Author.Login = "some-collaborator"
		rel.Assets = []githubAsset{{Name: darwinAssetName, BrowserDownloadURL: "https://example.com/a.zip"}}
		json.NewEncoder(w).Encode(rel)
	}))
	defer server.Close()

	if got := checkInternal(server.URL, "v1.0.0", checkTimeout).AssetURL; got != "" {
		t.Fatalf("AssetURL = %q, want empty", got)
	}
}

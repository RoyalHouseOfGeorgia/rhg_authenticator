package errorreport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
)

// --- BuildIssueTitle ---

func TestBuildIssueTitle_Normal(t *testing.T) {
	got := BuildIssueTitle("hardware", "YubiKey not responding")
	want := "[Auto] hardware: YubiKey not responding"
	if got != want {
		t.Errorf("BuildIssueTitle = %q, want %q", got, want)
	}
}

func TestBuildIssueTitle_Truncation(t *testing.T) {
	long := strings.Repeat("x", 300)
	got := BuildIssueTitle("internal", long)
	if len(got) != maxTitleLen {
		t.Errorf("title length = %d, want %d", len(got), maxTitleLen)
	}
	if !strings.HasPrefix(got, "[Auto] internal: ") {
		t.Errorf("title prefix wrong: %q", got[:30])
	}
}

func TestBuildIssueTitle_ExactLength(t *testing.T) {
	prefix := "[Auto] network: "
	desc := strings.Repeat("a", maxTitleLen-len(prefix))
	got := BuildIssueTitle("network", desc)
	if len(got) != maxTitleLen {
		t.Errorf("title length = %d, want %d", len(got), maxTitleLen)
	}
}

func TestBuildIssueTitle_MultibyteTruncation(t *testing.T) {
	// Place a 4-byte emoji so the 256-byte cut falls mid-rune.
	prefix := "[Auto] internal: "
	filler := strings.Repeat("A", maxTitleLen-len(prefix)-2) // leaves 2 bytes
	desc := filler + "\U0001F600"                            // 4-byte emoji, cut after 2 bytes
	got := BuildIssueTitle("internal", desc)
	if !isValidUTF8(got) {
		t.Error("truncated title is not valid UTF-8")
	}
	if len(got) > maxTitleLen {
		t.Errorf("title length = %d, exceeds %d", len(got), maxTitleLen)
	}
}

func isValidUTF8(s string) bool {
	return strings.ToValidUTF8(s, "\xff") == s
}

// --- BuildIssueBody ---

func TestBuildIssueBody_Fields(t *testing.T) {
	body := BuildIssueBody("v1.2.3", "signing", "signature failed")

	assertContains(t, body, "**Version:** v1.2.3")
	assertContains(t, body, "**OS:** "+runtime.GOOS+"/"+runtime.GOARCH)
	assertContains(t, body, "**Error type:** signing")
	assertContains(t, body, "**Error:** signature failed")
	assertContains(t, body, "*Auto-reported by RHG Authenticator*")

}

func TestBuildIssueBody_ControlCharsStripped(t *testing.T) {
	msg := "error\x00with\x1bcontrol\u202achars"
	body := BuildIssueBody("v1.0.0", "internal", msg)
	if strings.ContainsAny(body, "\x00\x1b") {
		t.Error("body contains control characters that should have been stripped")
	}
	if strings.Contains(body, "\u202a") {
		t.Error("body contains bidi override that should have been stripped")
	}
}

// --- ReportIssue: logged in ---

func TestReportIssue_LoggedIn_CreatesIssue(t *testing.T) {
	called := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok123" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer tok123")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(ghapi.IssueResult{
			Number:  99,
			HTMLURL: "https://github.com/test/repo/issues/99",
		})
	}))
	defer ts.Close()

	result, filed := ReportIssue(context.Background(), testClient("tok123", ts.URL), "Test Title", "Test Body")
	if !filed {
		t.Fatal("filed = false for an API-created issue")
	}
	if !called {
		t.Fatal("CreateIssue was not called")
	}
	if result != "https://github.com/test/repo/issues/99" {
		t.Errorf("result = %q, want issue URL", result)
	}
}

// --- ReportIssue: API error falls through to browser ---

func TestReportIssue_APIError_FallsThrough(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"message":"server error"}`))
	}))
	defer ts.Close()

	result, filed := ReportIssue(context.Background(), testClient("tok", ts.URL), "Title", "Body")
	if filed {
		t.Fatal("filed = true for a browser fallback")
	}
	assertBrowserURL(t, result, "Title")
}

// --- ReportIssue: no session (logged out or offline) ---

func TestReportIssue_NilClient_ReturnsBrowserURL(t *testing.T) {
	result, filed := ReportIssue(context.Background(), nil, "My Title", "My Body")
	if filed {
		t.Fatal("filed = true for a browser fallback")
	}
	assertBrowserURL(t, result, "My Title")
}

// --- Body truncation for browser path ---

func TestBrowserURL_BodyTruncation(t *testing.T) {
	longBody := strings.Repeat("A", 2000)
	u := browserURL("Title", longBody)

	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatalf("invalid URL: %v", err)
	}

	body := parsed.Query().Get("body")
	if !strings.HasSuffix(body, "and attach the file.") {
		t.Error("truncated body should end with truncation notice")
	}
	idx := strings.Index(body, "\n\nReport truncated")
	if idx < 0 {
		t.Fatal("truncation notice not found in body")
	}
	if idx > maxBrowserBodyBytes {
		t.Errorf("truncated body prefix = %d bytes, want <= %d", idx, maxBrowserBodyBytes)
	}
}

func TestBrowserURL_ShortBodyNotTruncated(t *testing.T) {
	shortBody := "Short body"
	u := browserURL("Title", shortBody)

	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatalf("invalid URL: %v", err)
	}
	body := parsed.Query().Get("body")
	if body != shortBody {
		t.Errorf("body = %q, want %q", body, shortBody)
	}
}

func TestBrowserURL_MultibyteTruncation(t *testing.T) {
	// Build a body with multi-byte characters near the cut point.
	// Each emoji is 4 bytes; place them so the cut falls mid-rune.
	prefix := strings.Repeat("A", maxBrowserBodyBytes-2)
	body := prefix + "\U0001F600\U0001F600" // two 4-byte emoji
	u := browserURL("Title", body)

	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatalf("invalid URL: %v", err)
	}
	decoded := parsed.Query().Get("body")
	// Should not contain broken UTF-8.
	if strings.ToValidUTF8(decoded, "\xff") != decoded {
		t.Error("truncated body contains invalid UTF-8")
	}
}

// --- Token never in body ---

func TestReportIssue_TokenNotInBody(t *testing.T) {
	token := "gho_supersecrettoken123"
	body := BuildIssueBody("v1.0.0", "internal", "error occurred")

	if strings.Contains(body, token) {
		t.Error("issue body contains token")
	}

	result, _ := ReportIssue(context.Background(), nil, "Title", body)
	if strings.Contains(result, token) {
		t.Error("result URL contains token")
	}
}

// --- helpers ---

// testClient returns a client with token that talks to baseURL.
func testClient(token, baseURL string) *ghapi.Client {
	c := ghapi.NewClient(token)
	c.BaseURL = baseURL
	return c
}

func assertContains(t *testing.T, s, sub string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Errorf("string does not contain %q:\n%s", sub, s)
	}
}

func assertBrowserURL(t *testing.T, u, expectedTitle string) {
	t.Helper()
	if !strings.HasPrefix(u, issueNewURL) {
		t.Errorf("URL = %q, want prefix %q", u, issueNewURL)
	}
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatalf("invalid URL: %v", err)
	}
	if got := parsed.Query().Get("title"); got != expectedTitle {
		t.Errorf("title param = %q, want %q", got, expectedTitle)
	}
}

// Tests in this file mutate package-level function vars and MUST NOT use t.Parallel().
package errorreport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
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
	desc := filler + "\U0001F600"                             // 4-byte emoji, cut after 2 bytes
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

func TestBuildIssueBody_NoDebugLog(t *testing.T) {
	body := BuildIssueBody("v1.2.3", "signing", "signature failed", "")

	assertContains(t, body, "**Version:** v1.2.3")
	assertContains(t, body, "**OS:** "+runtime.GOOS+"/"+runtime.GOARCH)
	assertContains(t, body, "**Error type:** signing")
	assertContains(t, body, "**Error:** signature failed")
	assertContains(t, body, "*Auto-reported by RHG Authenticator*")

	if strings.Contains(body, "Debug log") {
		t.Error("body should not contain debug log section when path is empty")
	}
}

func TestBuildIssueBody_WithDebugLog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "debug.log")

	var lines []string
	for i := range 60 {
		lines = append(lines, lineN(i))
	}
	if err := os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	body := BuildIssueBody("dev-abc1234", "internal", "panic", logPath)

	assertContains(t, body, "**Debug log (last 50 lines):**")
	// First 10 lines (0-9) should be trimmed; line 10 onward should remain.
	if strings.Contains(body, "line-00009\n") {
		t.Error("body should not contain lines outside tail window")
	}
	assertContains(t, body, "line-00059")
	assertContains(t, body, "line-00010")
}

func TestBuildIssueBody_MissingDebugLog(t *testing.T) {
	body := BuildIssueBody("v1.0.0", "network", "timeout", "/no/such/file")
	if strings.Contains(body, "Debug log") {
		t.Error("body should omit debug log for missing file")
	}
}

func TestBuildIssueBody_EmptyDebugLog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "empty.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	body := BuildIssueBody("v1.0.0", "hardware", "no key", logPath)
	if strings.Contains(body, "Debug log") {
		t.Error("body should omit debug log for empty file")
	}
}

func TestBuildIssueBody_ControlCharsStripped(t *testing.T) {
	msg := "error\x00with\x1bcontrol\u202achars"
	body := BuildIssueBody("v1.0.0", "internal", msg, "")
	if strings.ContainsAny(body, "\x00\x1b") {
		t.Error("body contains control characters that should have been stripped")
	}
	if strings.Contains(body, "\u202a") {
		t.Error("body contains bidi override that should have been stripped")
	}
}

func TestBuildIssueBody_InvalidUTF8InLog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "bad.log")
	if err := os.WriteFile(logPath, []byte("valid\xff\xfeinvalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	body := BuildIssueBody("v1.0.0", "internal", "err", logPath)
	assertContains(t, body, "Debug log")
	if strings.ToValidUTF8(body, "\xff") != body {
		t.Error("body contains invalid UTF-8 sequences")
	}
}

// --- ReportIssue: logged-in, online ---

func TestReportIssue_LoggedIn_CreatesIssue(t *testing.T) {
	origRestore := restoreSessionFunc
	origClient := newClientFunc
	t.Cleanup(func() {
		restoreSessionFunc = origRestore
		newClientFunc = origClient
	})

	restoreSessionFunc = func(_ context.Context, _ ghapi.Keyring, _ string) (ghapi.Token, string, bool, bool, error) {
		return ghapi.Token{AccessToken: "tok123"}, "testuser", true, false, nil
	}

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

	var capturedToken, capturedUser string
	newClientFunc = func(token, username string) *ghapi.Client {
		capturedToken = token
		capturedUser = username
		c := ghapi.NewClientWithUser(token, username)
		c.BaseURL = ts.URL
		return c
	}

	kr := ghapi.NewFakeKeyring()
	result, err := ReportIssue(context.Background(), kr, t.TempDir(), "Test Title", "Test Body")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("CreateIssue was not called")
	}
	if result != "https://github.com/test/repo/issues/99" {
		t.Errorf("result = %q, want issue URL", result)
	}
	if capturedToken != "tok123" {
		t.Errorf("token = %q, want %q", capturedToken, "tok123")
	}
	if capturedUser != "testuser" {
		t.Errorf("username = %q, want %q", capturedUser, "testuser")
	}
}

// --- ReportIssue: logged-in, API error falls through to browser ---

func TestReportIssue_APIError_FallsThrough(t *testing.T) {
	origRestore := restoreSessionFunc
	origClient := newClientFunc
	t.Cleanup(func() {
		restoreSessionFunc = origRestore
		newClientFunc = origClient
	})

	restoreSessionFunc = func(_ context.Context, _ ghapi.Keyring, _ string) (ghapi.Token, string, bool, bool, error) {
		return ghapi.Token{AccessToken: "tok"}, "user", true, false, nil
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"message":"server error"}`))
	}))
	defer ts.Close()

	newClientFunc = func(token, username string) *ghapi.Client {
		c := ghapi.NewClientWithUser(token, username)
		c.BaseURL = ts.URL
		return c
	}

	kr := ghapi.NewFakeKeyring()
	result, err := ReportIssue(context.Background(), kr, t.TempDir(), "Title", "Body")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBrowserURL(t, result, "Title")
}

// --- ReportIssue: logged-in, offline ---

func TestReportIssue_Offline_ReturnsBrowserURL(t *testing.T) {
	origRestore := restoreSessionFunc
	t.Cleanup(func() { restoreSessionFunc = origRestore })

	restoreSessionFunc = func(_ context.Context, _ ghapi.Keyring, _ string) (ghapi.Token, string, bool, bool, error) {
		return ghapi.Token{AccessToken: "tok"}, "", true, true, nil
	}

	kr := ghapi.NewFakeKeyring()
	result, err := ReportIssue(context.Background(), kr, t.TempDir(), "Title", "Body")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBrowserURL(t, result, "Title")
}

// --- ReportIssue: not logged in ---

func TestReportIssue_NotLoggedIn_ReturnsBrowserURL(t *testing.T) {
	origRestore := restoreSessionFunc
	t.Cleanup(func() { restoreSessionFunc = origRestore })

	restoreSessionFunc = func(_ context.Context, _ ghapi.Keyring, _ string) (ghapi.Token, string, bool, bool, error) {
		return ghapi.Token{}, "", false, false, nil
	}

	kr := ghapi.NewFakeKeyring()
	result, err := ReportIssue(context.Background(), kr, t.TempDir(), "My Title", "My Body")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBrowserURL(t, result, "My Title")
}

// --- ReportIssue: RestoreSession error ---

func TestReportIssue_SessionError_ReturnsBrowserURL(t *testing.T) {
	origRestore := restoreSessionFunc
	t.Cleanup(func() { restoreSessionFunc = origRestore })

	restoreSessionFunc = func(_ context.Context, _ ghapi.Keyring, _ string) (ghapi.Token, string, bool, bool, error) {
		return ghapi.Token{}, "", false, false, os.ErrPermission
	}

	kr := ghapi.NewFakeKeyring()
	result, err := ReportIssue(context.Background(), kr, t.TempDir(), "Title", "Body")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertBrowserURL(t, result, "Title")
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
	if !strings.HasSuffix(body, "attach full log from your config directory.") {
		t.Error("truncated body should end with truncation notice")
	}
	idx := strings.Index(body, "\n\nDebug log truncated")
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
	origRestore := restoreSessionFunc
	t.Cleanup(func() { restoreSessionFunc = origRestore })

	restoreSessionFunc = func(_ context.Context, _ ghapi.Keyring, _ string) (ghapi.Token, string, bool, bool, error) {
		return ghapi.Token{}, "", false, false, nil
	}

	token := "gho_supersecrettoken123"
	body := BuildIssueBody("v1.0.0", "internal", "error occurred", "")

	if strings.Contains(body, token) {
		t.Error("issue body contains token")
	}

	kr := ghapi.NewFakeKeyring()
	result, _ := ReportIssue(context.Background(), kr, t.TempDir(), "Title", body)
	if strings.Contains(result, token) {
		t.Error("result URL contains token")
	}
}

// --- readTail ---

func TestReadTail_ExactlyNLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exact.log")

	var lines []string
	for i := range debugLogTailLines {
		lines = append(lines, lineN(i))
	}
	os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)

	tail := readTail(path, debugLogTailLines)
	count := strings.Count(tail, "\n") + 1
	if count != debugLogTailLines {
		t.Errorf("tail has %d lines, want %d", count, debugLogTailLines)
	}
}

func TestReadTail_FewerThanNLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "few.log")
	os.WriteFile(path, []byte("line1\nline2\nline3\n"), 0o600)

	tail := readTail(path, debugLogTailLines)
	if !strings.Contains(tail, "line1") || !strings.Contains(tail, "line3") {
		t.Errorf("tail = %q, want all 3 lines", tail)
	}
}

// --- helpers ---

func lineN(n int) string {
	s := ""
	if n < 10 {
		s = "0000" + string(rune('0'+n))
	} else if n < 100 {
		s = "000" + string(rune('0'+n/10)) + string(rune('0'+n%10))
	} else {
		s = "00" + string(rune('0'+n/100)) + string(rune('0'+(n/10)%10)) + string(rune('0'+n%10))
	}
	return "line-" + s
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

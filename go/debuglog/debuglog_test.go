package debuglog

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNew_EmptyPath_NoOp(t *testing.T) {
	logger := New("")
	// Should not panic or create any file.
	logger.Log("should be a no-op")
	logger.Logf("also %s", "no-op")
}

func TestNew_CreatesFileAndWritesEntry(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "debug.log")
	logger := New(logPath)
	logger.Log("test message")

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}
	if !strings.Contains(string(data), "test message") {
		t.Errorf("log file does not contain message: %q", string(data))
	}
}

func TestNilLogger_NoPanic(t *testing.T) {
	var logger *Logger
	// None of these should panic.
	logger.Log("should not panic")
	logger.Logf("should not %s", "panic")
	if p := logger.Path(); p != "" {
		t.Errorf("Path() = %q, want empty", p)
	}
}

func TestLogf_FormatsMessage(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "debug.log")
	logger := New(logPath)
	logger.Logf("count=%d name=%s", 42, "test")

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}
	if !strings.Contains(string(data), "count=42 name=test") {
		t.Errorf("formatted message not found in log: %q", string(data))
	}
}

func TestAppendMode(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "debug.log")
	logger := New(logPath)

	logger.Log("first message")
	logger.Log("second message")

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 lines, got %d: %q", len(lines), string(data))
	}
	if !strings.Contains(lines[0], "first message") {
		t.Errorf("first line missing expected content: %q", lines[0])
	}
	if !strings.Contains(lines[1], "second message") {
		t.Errorf("second line missing expected content: %q", lines[1])
	}
}

func TestFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permissions not supported on Windows")
	}
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "debug.log")
	logger := New(logPath)
	logger.Log("perm check")

	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("file permissions = %o, want 0600", perm)
	}
}

func TestSanitizesControlChars(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "debug.log")
	logger := New(logPath)
	logger.Log("line1\ninjected\r\x00hidden")

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}
	content := string(data)
	// The message itself should not contain raw control chars (only the
	// trailing newline from fmt.Fprintf is allowed).
	lines := strings.Split(strings.TrimSpace(content), "\n")
	if len(lines) != 1 {
		t.Errorf("expected 1 line (control chars sanitized), got %d: %q", len(lines), content)
	}
	if strings.Contains(lines[0], "\x00") {
		t.Errorf("null byte not sanitized: %q", lines[0])
	}
	if !strings.Contains(lines[0], "line1 injected  hidden") {
		t.Errorf("sanitized content unexpected: %q", lines[0])
	}
}

func TestDoesNotTruncateLongMessages(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "debug.log")
	logger := New(logPath)

	longMsg := strings.Repeat("x", 650)
	logger.Log(longMsg)

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}
	if !strings.Contains(string(data), longMsg) {
		t.Errorf("long message was truncated: got %d bytes, message has 650 chars", len(data))
	}
}

func TestTimestampFormat(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "debug.log")
	logger := New(logPath)

	before := time.Now().UTC()
	logger.Log("ts check")
	after := time.Now().UTC()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}
	line := strings.TrimSpace(string(data))
	// Expect format: [2006-01-02T15:04:05Z] ts check
	if !strings.HasPrefix(line, "[") {
		t.Fatalf("line does not start with '[': %q", line)
	}
	closeBracket := strings.Index(line, "]")
	if closeBracket < 0 {
		t.Fatalf("no closing bracket found: %q", line)
	}
	tsStr := line[1:closeBracket]
	ts, err := time.Parse(time.RFC3339, tsStr)
	if err != nil {
		t.Fatalf("timestamp %q does not parse as RFC3339: %v", tsStr, err)
	}
	if ts.Before(before.Add(-time.Second)) || ts.After(after.Add(time.Second)) {
		t.Errorf("timestamp %v outside expected range [%v, %v]", ts, before, after)
	}
}

func TestPath_ReturnsPath(t *testing.T) {
	logger := New("/tmp/test.log")
	if got := logger.Path(); got != "/tmp/test.log" {
		t.Errorf("Path() = %q, want %q", got, "/tmp/test.log")
	}
}

func TestPath_EmptyForNoOp(t *testing.T) {
	logger := New("")
	if got := logger.Path(); got != "" {
		t.Errorf("Path() = %q, want empty", got)
	}
}

func TestLog_OpenFileError(t *testing.T) {
	// Use a path in a non-existent directory to trigger OpenFile failure.
	logger := New("/nonexistent/dir/debug.log")
	// Should not panic — just silently discard.
	logger.Log("should not panic")
}

package debuglog

import (
	stdlog "log"
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

func TestPruneLines(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	maxAge := 30 * 24 * time.Hour
	ts := func(d time.Duration) string { return now.Add(-d).Format(time.RFC3339) }
	fresh1 := "[" + ts(time.Hour) + "] fresh one\n"
	fresh2 := "[" + ts(29*24*time.Hour) + "] fresh two\n"
	stale1 := "[" + ts(31*24*time.Hour) + "] stale one\n"
	stale2 := "[" + ts(365*24*time.Hour) + "] stale two\n"
	boundary := "[" + ts(maxAge) + "] boundary\n"
	justStale := "[" + ts(maxAge+time.Second) + "] just stale\n"
	future := "[" + ts(-48*time.Hour) + "] future\n"

	tests := []struct {
		name        string
		in          string
		want        string
		wantDropped bool
	}{
		{"empty", "", "", false},
		{"all fresh", fresh1 + fresh2, fresh1 + fresh2, false},
		{"all stale", stale1 + stale2, "", true},
		{"mixed", stale1 + fresh1 + stale2 + fresh2, fresh1 + fresh2, true},
		{"boundary kept", boundary, boundary, false},
		{"one second past boundary dropped", justStale + fresh1, fresh1, true},
		{"future kept", future, future, false},
		{
			"untimestamped and malformed dropped",
			"PANIC: boom\n" + fresh1 + "goroutine 1 [running]:\n" +
				"[not-a-date-at-all-xx] x\n" + "[2026-01-02T03:04:05+02:00] x\n" +
				"\n" + "[2026-09-30T11:00:00Z\n" + fresh2,
			fresh1 + fresh2,
			true,
		},
		{"torn final line gets newline", fresh1 + strings.TrimSuffix(fresh2, "\n"), fresh1 + fresh2, true},
		{"torn final line dropped", fresh1 + "[2026-09-3", fresh1, true},
		{"blank-only input", "\n", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, dropped := pruneLines([]byte(tt.in), maxAge, now)
			if string(out) != tt.want {
				t.Errorf("out = %q, want %q", out, tt.want)
			}
			if dropped != tt.wantDropped {
				t.Errorf("dropped = %v, want %v", dropped, tt.wantDropped)
			}
		})
	}
}

func TestPrune_MissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	if err := Prune(path, LogRetention, time.Now()); err != nil {
		t.Fatalf("Prune on missing file: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("Prune created %s (stat err = %v)", path, err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("Prune created tmp file (stat err = %v)", err)
	}
}

func TestPrune_NoDropLeavesFileUntouched(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	now := time.Now()
	content := "[" + now.UTC().Add(-time.Hour).Format(time.RFC3339) + "] keep\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	if err := Prune(path, LogRetention, now); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().Equal(old) {
		t.Errorf("mtime changed to %v, want %v (file was rewritten)", info.ModTime(), old)
	}
}

func TestPrune_RewritesKeptLinesOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	now := time.Now()
	keep := "[" + now.UTC().Add(-time.Hour).Format(time.RFC3339) + "] keep\n"
	stale := "[" + now.UTC().Add(-40*24*time.Hour).Format(time.RFC3339) + "] stale\n"
	// Pre-create with a looser mode to prove the rewrite enforces 0600.
	if err := os.WriteFile(path, []byte("PANIC: legacy\n"+stale+keep), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Prune(path, LogRetention, now); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != keep {
		t.Errorf("content = %q, want %q", data, keep)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("tmp file left behind (stat err = %v)", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("mode = %o, want 0600", perm)
		}
	}
}

func TestPrune_StaleTmpReplaced(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	if err := os.WriteFile(path, []byte("PANIC: legacy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".tmp", []byte("leftover garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Prune(path, LogRetention, time.Now()); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Errorf("content = %q, want empty", data)
	}
}

func TestPrune_ReadError(t *testing.T) {
	// A directory at the log path makes ReadFile fail with a non-ENOENT error.
	path := t.TempDir()
	if err := Prune(path, LogRetention, time.Now()); err == nil {
		t.Error("Prune on a directory: want error, got nil")
	}
}

func TestPrune_TmpCreateError(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	if err := os.WriteFile(path, []byte("PANIC: legacy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A non-empty directory at the tmp path survives os.Remove and blocks OpenFile.
	tmp := path + ".tmp"
	if err := os.MkdirAll(filepath.Join(tmp, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := Prune(path, LogRetention, time.Now()); err == nil {
		t.Error("Prune with blocked tmp path: want error, got nil")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "PANIC: legacy\n" {
		t.Errorf("original log modified on failure: %q", data)
	}
}

func TestWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	logger := New(path)
	p := []byte("hello world\n\n")
	n, err := logger.Write(p)
	if n != len(p) || err != nil {
		t.Errorf("Write = (%d, %v), want (%d, nil)", n, err, len(p))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line := string(data)
	if !strings.HasSuffix(line, "] hello world\n") || strings.Count(line, "\n") != 1 {
		t.Errorf("log content = %q, want one entry ending in \"hello world\"", line)
	}
}

func TestWrite_NilAndNoOpLoggers(t *testing.T) {
	p := []byte("discarded\n")
	for name, logger := range map[string]*Logger{"nil": nil, "no-op": New("")} {
		n, err := logger.Write(p)
		if n != len(p) || err != nil {
			t.Errorf("%s: Write = (%d, %v), want (%d, nil)", name, n, err, len(p))
		}
	}
}

func TestWrite_UnwritableFileStillSucceeds(t *testing.T) {
	logger := New("/nonexistent/dir/debug.log")
	p := []byte("lost\n")
	if n, err := logger.Write(p); n != len(p) || err != nil {
		t.Errorf("Write = (%d, %v), want (%d, nil)", n, err, len(p))
	}
}

func TestStdlibRoundTripAndRetention(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	stdlog.New(New(path), "", 0).Printf("a\nb")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(data), "\n"); got != 1 {
		t.Fatalf("got %d lines, want 1: %q", got, data)
	}

	if err := Prune(path, LogRetention, time.Now().Add(29*24*time.Hour)); err != nil {
		t.Fatalf("Prune at +29d: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(data) {
		t.Errorf("entry changed at +29d: %q, want %q", after, data)
	}

	if err := Prune(path, LogRetention, time.Now().Add(31*24*time.Hour)); err != nil {
		t.Fatalf("Prune at +31d: %v", err)
	}
	after, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 0 {
		t.Errorf("entry survived +31d: %q", after)
	}
}

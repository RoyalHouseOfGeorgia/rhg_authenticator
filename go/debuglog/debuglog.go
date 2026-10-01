// Package debuglog provides the app's always-on diagnostic log: an
// append-only, one-entry-per-line file logger whose entries are pruned
// after LogRetention (30 days) by Prune.
package debuglog

import (
	"bytes"
	"fmt"
	"io"
	stdlog "log"
	"os"
	"strings"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

// FileName is the diagnostic log's file name within the app's data directory.
const FileName = "debug.log"

// LogRetention is how long log entries are kept before Prune drops them.
const LogRetention = 30 * 24 * time.Hour

// Logger appends timestamped messages to a log file. A nil or
// zero-value Logger silently discards all messages.
type Logger struct {
	path string
}

// New returns a Logger that writes to the given path. An empty path
// creates a no-op logger that silently discards all messages.
func New(path string) *Logger {
	return &Logger{path: path}
}

// Log appends a timestamped, sanitized message to the log file.
func (l *Logger) Log(msg string) {
	if l == nil || l.path == "" {
		return
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "[%s] %s\n", time.Now().UTC().Format(time.RFC3339), core.StripControlChars(msg))
}

// Logf formats and logs a message.
func (l *Logger) Logf(format string, args ...any) {
	if l == nil || l.path == "" {
		return
	}
	l.Log(fmt.Sprintf(format, args...))
}

// Path returns the log file path, or "" for no-op loggers.
func (l *Logger) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

// Write implements io.Writer by logging p as a single entry with trailing
// newlines trimmed. It always reports success so that a failing log file
// never breaks a writer chain (e.g. io.MultiWriter). Nil-safe via Log.
func (l *Logger) Write(p []byte) (int, error) {
	l.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// CaptureStdlib routes the standard library logger to l (and stderr).
func CaptureStdlib(l *Logger) {
	stdlog.SetFlags(0)
	// l must come first: on Windows GUI builds (-H windowsgui) writes to
	// os.Stderr fail, and io.MultiWriter stops at the first error.
	stdlog.SetOutput(io.MultiWriter(l, os.Stderr))
}

// tsLen is the length of the "[2006-01-02T15:04:05Z]" prefix Log writes.
const tsLen = len("[2006-01-02T15:04:05Z]")

// pruneLines keeps only lines that start with a Log-style UTC timestamp no
// older than maxAge relative to now. Untimestamped lines (legacy panic dumps),
// torn lines and malformed timestamps are dropped. Future timestamps (clock
// skew) are kept. Non-empty output always ends with "\n".
//
// dropped reports whether out differs from data: besides dropped lines, a
// kept final line lacking its "\n" also counts, so Prune rewrites the file
// and later appends start on a fresh line instead of merging into it.
func pruneLines(data []byte, maxAge time.Duration, now time.Time) (out []byte, dropped bool) {
	if len(data) == 0 {
		return nil, false
	}
	body := data
	if body[len(body)-1] == '\n' {
		body = body[:len(body)-1]
	} else {
		dropped = true
	}
	out = make([]byte, 0, len(data)+1)
	for _, line := range bytes.Split(body, []byte("\n")) {
		if keepLine(line, maxAge, now) {
			out = append(out, line...)
			out = append(out, '\n')
		} else {
			dropped = true
		}
	}
	return out, dropped
}

func keepLine(line []byte, maxAge time.Duration, now time.Time) bool {
	if len(line) < tsLen || line[0] != '[' || line[tsLen-1] != ']' {
		return false
	}
	ts, err := time.Parse(time.RFC3339, string(line[1:tsLen-1]))
	if err != nil {
		return false
	}
	return now.Sub(ts) <= maxAge
}

// Prune rewrites the log at path, dropping entries older than maxAge and any
// lines without a valid timestamp. A missing file is not an error, and the
// file is left untouched when nothing would change. The rewrite goes through
// a temporary file and rename so a crash never leaves a half-written log.
func Prune(path string, maxAge time.Duration, now time.Time) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read log for pruning: %w", err)
	}
	out, dropped := pruneLines(data, maxAge, now)
	if !dropped {
		return nil
	}
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	if err := writeFile(tmp, out); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace pruned log: %w", err)
	}
	return nil
}

func writeFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create pruned log: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write pruned log: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close pruned log: %w", err)
	}
	return nil
}

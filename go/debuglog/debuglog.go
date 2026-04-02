// Package debuglog provides a simple append-only file logger for debug builds.
package debuglog

import (
	"fmt"
	"os"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

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

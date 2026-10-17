package service

import (
	"strings"
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
)

// --- FormatCommitSummary tests ---

func TestFormatCommitSummary(t *testing.T) {
	c := ghapi.RegistryCommit{SHA: "abc123"}
	c.Commit.Message = "Fix registry"
	c.Commit.Author.Name = "Kimon"
	c.Commit.Author.Date = "2026-03-15T10:00:00Z"

	got := FormatCommitSummary(c)
	want := "2026-Mar-15  Kimon — Fix registry"
	if got != want {
		t.Errorf("FormatCommitSummary = %q, want %q", got, want)
	}
}

func TestFormatCommitSummary_LongMessage(t *testing.T) {
	c := ghapi.RegistryCommit{}
	c.Commit.Message = strings.Repeat("a", 100)
	c.Commit.Author.Name = "Author"
	c.Commit.Author.Date = "2026-03-15T10:00:00Z"

	got := FormatCommitSummary(c)
	if !strings.HasSuffix(got, "...") {
		t.Error("long message should be truncated with '...'")
	}
	// The message portion should be 80 runes + "..."
	// Extract the part after " — "
	parts := strings.SplitN(got, " — ", 2)
	if len(parts) != 2 {
		t.Fatalf("unexpected format: %q", got)
	}
	msgRunes := []rune(parts[1])
	// 80 runes + 3 for "..."
	if len(msgRunes) != 83 {
		t.Errorf("truncated message rune count = %d, want 83", len(msgRunes))
	}
}

func TestFormatCommitSummary_MultilineMessage(t *testing.T) {
	c := ghapi.RegistryCommit{}
	c.Commit.Message = "line1\nline2\nline3"
	c.Commit.Author.Name = "Author"
	c.Commit.Author.Date = "2026-03-15T10:00:00Z"

	got := FormatCommitSummary(c)
	if strings.Contains(got, "line2") {
		t.Error("multiline message should only show first line")
	}
	if !strings.Contains(got, "line1") {
		t.Error("should contain first line")
	}
}

func TestFormatCommitSummary_EmptyFields(t *testing.T) {
	c := ghapi.RegistryCommit{}
	c.Commit.Message = ""
	c.Commit.Author.Name = ""
	c.Commit.Author.Date = "not-a-date"

	got := FormatCommitSummary(c)
	if !strings.Contains(got, "Unknown") {
		t.Errorf("empty author should show 'Unknown', got: %q", got)
	}
	if !strings.Contains(got, "(no message)") {
		t.Errorf("empty message should show '(no message)', got: %q", got)
	}
	if !strings.Contains(got, "not-a-date") {
		t.Errorf("bad date should use raw string, got: %q", got)
	}
}

// --- truncateRunes tests ---

func TestTruncateRunes_Short(t *testing.T) {
	got := truncateRunes("Short", 50)
	if got != "Short" {
		t.Errorf("truncateRunes = %q, want %q", got, "Short")
	}
}

func TestTruncateRunes_ExactLength(t *testing.T) {
	s := strings.Repeat("a", 50)
	got := truncateRunes(s, 50)
	if got != s {
		t.Errorf("truncateRunes exact = %q, want %q", got, s)
	}
}

func TestTruncateRunes_Long(t *testing.T) {
	s := strings.Repeat("a", 60)
	got := truncateRunes(s, 50)
	want := strings.Repeat("a", 50) + "..."
	if got != want {
		t.Errorf("truncateRunes long = %q, want %q", got, want)
	}
}

func TestTruncateRunes_Unicode(t *testing.T) {
	// Georgian characters are multi-byte but each is one rune.
	s := strings.Repeat("\u10D0", 55) // 55 Georgian "a" runes
	got := truncateRunes(s, 50)
	wantPrefix := strings.Repeat("\u10D0", 50) + "..."
	if got != wantPrefix {
		t.Errorf("truncateRunes unicode length mismatch")
	}
}

func TestTruncateRunes_Empty(t *testing.T) {
	got := truncateRunes("", 50)
	if got != "" {
		t.Errorf("truncateRunes empty = %q, want empty", got)
	}
}

func TestTruncateRunes_ZeroMax(t *testing.T) {
	got := truncateRunes("anything", 0)
	if got != "" {
		t.Errorf("truncateRunes zero max = %q, want empty", got)
	}
}

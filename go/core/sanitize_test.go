package core

import (
	"strings"
	"testing"
)

func TestSanitizeForLog(t *testing.T) {
	tests := []struct {
		name  string
		input string
		check func(t *testing.T, result string)
	}{
		{
			name:  "control characters replaced",
			input: "line1\nline2\rline3\ttab\x00null",
			check: func(t *testing.T, result string) {
				if strings.ContainsAny(result, "\n\r\t\x00") {
					t.Errorf("result contains control chars: %q", result)
				}
				if !strings.Contains(result, "line1 line2 line3 tab null") {
					t.Errorf("unexpected result: %q", result)
				}
			},
		},
		{
			name:  "long string truncated at 500 runes",
			input: strings.Repeat("\U0001F600", 600), // 600 emoji (each 4 bytes)
			check: func(t *testing.T, result string) {
				runes := []rune(result)
				if len(runes) != MaxLogRunes {
					t.Errorf("rune count = %d, want %d", len(runes), MaxLogRunes)
				}
			},
		},
		{
			name:  "null bytes replaced",
			input: "a\x00b\x00c",
			check: func(t *testing.T, result string) {
				if strings.Contains(result, "\x00") {
					t.Errorf("result contains null bytes: %q", result)
				}
				if result != "a b c" {
					t.Errorf("result = %q, want %q", result, "a b c")
				}
			},
		},
		{
			name:  "short clean string unchanged",
			input: "hello world",
			check: func(t *testing.T, result string) {
				if result != "hello world" {
					t.Errorf("result = %q, want %q", result, "hello world")
				}
			},
		},
		{
			name:  "empty string",
			input: "",
			check: func(t *testing.T, result string) {
				if result != "" {
					t.Errorf("result = %q, want empty", result)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeForLog(tt.input)
			tt.check(t, result)
		})
	}
}

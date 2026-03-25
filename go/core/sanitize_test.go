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
		{
			name:  "DEL character replaced",
			input: "hello\x7fworld",
			check: func(t *testing.T, result string) {
				if result != "hello world" {
					t.Errorf("result = %q, want %q", result, "hello world")
				}
			},
		},
		{
			name:  "C1 characters replaced",
			input: "a" + string(rune(0x80)) + "b" + string(rune(0x9f)) + "c",
			check: func(t *testing.T, result string) {
				if result != "a b c" {
					t.Errorf("result = %q, want %q", result, "a b c")
				}
			},
		},
		{
			name:  "bidi override characters replaced",
			input: "left\u202aright\u2069end",
			check: func(t *testing.T, result string) {
				if result != "left right end" {
					t.Errorf("result = %q, want %q", result, "left right end")
				}
			},
		},
		{
			name:  "boundary 0x1f replaced",
			input: "a\x1fb",
			check: func(t *testing.T, result string) {
				if result != "a b" {
					t.Errorf("result = %q, want %q", result, "a b")
				}
			},
		},
		{
			name:  "boundary 0x20 space preserved",
			input: "a b",
			check: func(t *testing.T, result string) {
				if result != "a b" {
					t.Errorf("result = %q, want %q", result, "a b")
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

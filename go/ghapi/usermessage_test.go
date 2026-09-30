package ghapi

import (
	"errors"
	"fmt"
	"testing"
)

const (
	msgFork      = "Could not set up your GitHub fork. Check your network connection and try again."
	msgRateLimit = "GitHub rate limit reached. Try again in a few minutes."
	msgForbidden = "Permission denied. Check your GitHub account permissions."
	msgGeneric   = "An error occurred. Please try again later."
)

func TestUserMessage(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"rate limited", &APIError{StatusCode: 429, Message: "rate limit exceeded"}, msgRateLimit},
		{"forbidden", &APIError{StatusCode: 403, Message: "forbidden"}, msgForbidden},
		{"generic API error", &APIError{StatusCode: 500, Message: "internal server error"}, msgGeneric},
		{"network error", errors.New("dial tcp: lookup api.github.com: no such host"), msgGeneric},
		{"wrapped rate limited", fmt.Errorf("request failed: %w", &APIError{StatusCode: 429, Message: "rate limit"}), msgRateLimit},
		{"wrapped forbidden", fmt.Errorf("request failed: %w", &APIError{StatusCode: 403, Message: "forbidden"}), msgForbidden},
		{"nil error", nil, msgGeneric},
		{"fork error", &ForkError{Phase: "create", Wrapped: fmt.Errorf("network error")}, msgFork},
		{"wrapped fork error", fmt.Errorf("request failed: %w", &ForkError{Phase: "poll", Wrapped: fmt.Errorf("timeout")}), msgFork},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := UserMessage(tt.err); got != tt.want {
				t.Errorf("UserMessage(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

func TestUserMessage_DoesNotLeakDetails(t *testing.T) {
	// Ensure internal error details are not exposed to the user.
	err := errors.New("connection refused to 10.0.0.1:443: TLS handshake timeout")
	if got := UserMessage(err); got != msgGeneric {
		t.Errorf("UserMessage should not leak internal details, got %q", got)
	}
}

// TestUserMessage_ForkErrorPrecedence pins the precedence: a ForkError
// wrapping a 403/429 *APIError must yield the fork message (fork wins over
// permission/rate-limit), while a bare 403 still yields the forbidden message.
func TestUserMessage_ForkErrorPrecedence(t *testing.T) {
	forkOver403 := &ForkError{Phase: "create", Wrapped: &APIError{StatusCode: 403, Message: "forbidden"}}
	if got := UserMessage(forkOver403); got != msgFork {
		t.Errorf("UserMessage(ForkError wrapping 403) = %q, want %q", got, msgFork)
	}

	forkOver429 := &ForkError{Phase: "poll", Wrapped: &APIError{StatusCode: 429, Message: "rate limited"}}
	if got := UserMessage(forkOver429); got != msgFork {
		t.Errorf("UserMessage(ForkError wrapping 429) = %q, want %q", got, msgFork)
	}

	bare403 := &APIError{StatusCode: 403, Message: "forbidden"}
	if got := UserMessage(bare403); got != msgForbidden {
		t.Errorf("UserMessage(bare 403) = %q, want %q", got, msgForbidden)
	}
}

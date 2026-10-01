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
		// Fork wins over the permission/rate-limit message it wraps.
		{"fork over 403", &ForkError{Phase: "create", Wrapped: &APIError{StatusCode: 403, Message: "forbidden"}}, msgFork},
		{"fork over 429", &ForkError{Phase: "poll", Wrapped: &APIError{StatusCode: 429, Message: "rate limited"}}, msgFork},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := UserMessage(tt.err); got != tt.want {
				t.Errorf("UserMessage(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

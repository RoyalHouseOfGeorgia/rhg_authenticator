package ghapi

import (
	"errors"
	"fmt"
	"testing"
)

const (
	msgNoWrite   = "Your GitHub account can't submit changes to this repository. Ask the maintainer to add you as a collaborator."
	msgRateLimit = "GitHub rate limit reached. Try again in a few minutes."
	msgForbidden = "Permission denied. Check your GitHub account permissions."
	msgGeneric   = "An error occurred. Please try again later."
	msgRevoked   = "This credential is already revoked."
	msgPending   = "A revocation for this credential is already awaiting review on GitHub."
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
		{"already revoked", ErrAlreadyRevoked, msgRevoked},
		{"revocation pending", ErrRevocationPending, msgPending},
		{"no write access", ErrNoWriteAccess, msgNoWrite},
		{"wrapped no write access", fmt.Errorf("submit: %w", ErrNoWriteAccess), msgNoWrite},
		// A failed access check is a plain request error, not ErrNoWriteAccess.
		{"access check failed", fmt.Errorf("checking repository access: %w", &APIError{StatusCode: 500, Message: "boom"}), msgGeneric},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := UserMessage(tt.err); got != tt.want {
				t.Errorf("UserMessage(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

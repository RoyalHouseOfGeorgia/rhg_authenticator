package core

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestSafeRedirect_AllowsHTTPS(t *testing.T) {
	target, _ := url.Parse("https://cdn.example.com/path")
	req := &http.Request{URL: target}
	via := []*http.Request{{}}
	if err := SafeRedirect(req, via); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSafeRedirect_RejectsHTTP(t *testing.T) {
	target, _ := url.Parse("http://evil.com/path")
	req := &http.Request{URL: target}
	via := []*http.Request{{}}
	err := SafeRedirect(req, via)
	if err == nil {
		t.Fatal("expected error for HTTP redirect")
	}
	if !strings.Contains(err.Error(), "non-HTTPS") {
		t.Errorf("error should mention non-HTTPS, got: %v", err)
	}
}

func TestSafeRedirect_RejectsExcessiveRedirects(t *testing.T) {
	target, _ := url.Parse("https://example.com/path")
	req := &http.Request{URL: target}
	via := make([]*http.Request, 10)
	for i := range via {
		via[i] = &http.Request{}
	}
	err := SafeRedirect(req, via)
	if err == nil {
		t.Fatal("expected error after 10 redirects")
	}
	if !strings.Contains(err.Error(), "10 redirects") {
		t.Errorf("error should mention redirect limit, got: %v", err)
	}
}

func TestSafeRedirect_EmptyVia(t *testing.T) {
	target, _ := url.Parse("https://example.com/path")
	req := &http.Request{URL: target}
	if err := SafeRedirect(req, nil); err != nil {
		t.Fatalf("unexpected error for empty via: %v", err)
	}
}

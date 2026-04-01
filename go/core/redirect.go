package core

import (
	"errors"
	"fmt"
	"net/http"
)

// SafeRedirect rejects non-HTTPS redirects and enforces a 10-redirect limit.
// For unauthenticated HTTP clients only — these should never follow non-HTTPS redirects.
//
// Authenticated clients should use a separate redirect handler that also strips
// the Authorization header on cross-host redirects.
func SafeRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("redirect to non-HTTPS URL rejected")
	}
	return nil
}

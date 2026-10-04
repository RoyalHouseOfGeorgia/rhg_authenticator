package update

import "net/url"

// isHTTPSURL reports whether raw is an absolute https URL with a host.
func isHTTPSURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

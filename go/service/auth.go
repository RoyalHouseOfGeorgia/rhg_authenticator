package service

// ResolveLoginState determines the login display state from validation results.
// Pure function — no side effects, no ghapi dependency in the body.
func ResolveLoginState(isUnauthorized bool, username string, hasError bool) (loggedIn, offline bool, statusText string) {
	if isUnauthorized {
		return false, false, "Not logged in"
	}
	if hasError {
		return true, true, "GitHub unreachable"
	}
	return true, false, "Logged in as @" + username
}

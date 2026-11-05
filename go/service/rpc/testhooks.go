//go:build !rhgfake

package rpc

// addTestMethods adds the rhgfake test build's methods and fakes to a new
// server (testhooks_rhgfake.go). A production build has none.
func addTestMethods(*server) {}

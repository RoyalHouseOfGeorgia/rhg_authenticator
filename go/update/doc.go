// Package update checks GitHub Releases for a newer version and, on macOS,
// installs it in place.
//
// Flow: Check finds the latest workflow-published vX.Y.Z release and its
// macOS asset → download fetches the zip into the staging root → stage
// pre-scans, extracts and verifies it (pinned code-signing requirement,
// sealed version == tag, executable main binary) into staged-<ver>/ →
// apply swaps it with the running bundle on quit. Other platforms only get
// the version check (the app then shows a Download link). VerifyZipCLI runs
// the same stage path read-only for release CI.
package update

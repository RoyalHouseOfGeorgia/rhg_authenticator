//go:build !windows

package gui

import (
	"os"
	"path/filepath"
)

// desktopPath returns <home>/Desktop, or "" if the home directory is unknown.
func desktopPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "Desktop")
}

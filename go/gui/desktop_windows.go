package gui

import "golang.org/x/sys/windows"

// desktopPath returns the Desktop folder the shell reports, which follows
// redirection (OneDrive "Back up Desktop" moves it to OneDrive\Desktop), or ""
// if it can't be found. KF_FLAG_DEFAULT makes the shell fail when the folder
// doesn't exist; don't switch to KF_FLAG_CREATE (the app must not create
// folders in OneDrive) or KF_FLAG_DONT_VERIFY. A Desktop on a network share
// is best-effort: if the share is unreachable, the save dialog can freeze for
// the network timeout before opening in its default folder.
func desktopPath() string {
	p, err := windows.KnownFolderPath(windows.FOLDERID_Desktop, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return ""
	}
	return p
}

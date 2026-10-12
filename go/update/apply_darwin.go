//go:build darwin

package update

import (
	"os/exec"

	"golang.org/x/sys/unix"
)

// swapBundles atomically exchanges the two directory entries (both must be
// on the same volume). Either both names swap or neither does.
func swapBundles(staged, current string) error {
	return unix.RenamexNp(staged, current, unix.RENAME_SWAP)
}

// relaunch starts a new instance of the app at bundle without waiting for it.
// Call it as the very last action before exiting.
func relaunch(bundle string) error {
	name, args := relaunchCommand(bundle)
	cmd := exec.Command(name, args...)
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

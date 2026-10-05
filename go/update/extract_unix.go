//go:build unix

package update

import "syscall"

// openNoFollow makes extractFile refuse to open a symlink at the target path.
const openNoFollow = syscall.O_NOFOLLOW

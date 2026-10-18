package service

import "golang.org/x/sys/windows"

// platformReadOnlyErrors are the Windows read-only filesystem errors.
var platformReadOnlyErrors = []error{windows.ERROR_WRITE_PROTECT}

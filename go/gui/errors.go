package gui

import (
	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

// classifyHardwareError delegates to core.ClassifyHardwareError for backward
// compatibility within the gui package.
func classifyHardwareError(err error) string {
	return core.ClassifyHardwareError(err)
}

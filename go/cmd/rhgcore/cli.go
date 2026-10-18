package main

import (
	"io"

	"github.com/royalhouseofgeorgia/rhg-authenticator/buildinfo"
	"github.com/royalhouseofgeorgia/rhg-authenticator/host"
)

// mainCLI runs host.RunCLI on argv, a C main's argument vector (argv[0], the
// program name, is skipped). It returns -1 when argv is not a command-line
// invocation (or is empty), else the process exit code.
func mainCLI(argv []string, stdout, stderr io.Writer) int {
	if len(argv) == 0 {
		return -1
	}
	return host.RunCLI(argv[1:], version(), stdout, stderr)
}

// version is the version --version prints: the build's, marked in the
// rhgfake build.
func version() string { return buildinfo.Version + versionSuffix }

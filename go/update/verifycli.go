package update

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// Exit codes of VerifyZipCLI.
const (
	verifyExitOK    = 0
	verifyExitFail  = 1
	verifyExitUsage = 2
)

const verifyZipUsage = "usage: rhg-authenticator --verify-update-zip <zip> <tag> [--requirement <req>]"

// VerifyZipCLI implements `--verify-update-zip <zip> <tag> [--requirement <req>]`
// (args excludes the flag itself). It runs the app's real install-time check,
// stage, against zip: the archive must pass scanZip and extract cleanly, and
// its bundle must satisfy the code-signing requirement (PinnedRequirement
// unless overridden) and carry the version named by tag.
//
// It is read-only on its input: staging happens in a fresh temp dir that is
// always removed, the zip is never deleted, and the app data dir is never
// touched. Returns 0 if the zip verifies, 1 if it does not, 2 on a usage
// error. Release CI runs this against the exact zip it publishes.
func VerifyZipCLI(args []string, stdout, stderr io.Writer) int {
	return verifyZipCLI(args, stdout, stderr, pinnedVerifier, "")
}

// verifyZipCLI is VerifyZipCLI with an injectable verifier constructor and
// temp-dir base ("" = the OS default), for tests.
func verifyZipCLI(args []string, stdout, stderr io.Writer, newVerifier func(requirement string) verifier, tmpBase string) int {
	zipPath, tag, requirement, err := parseVerifyZipArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n%s\n", err, verifyZipUsage)
		return verifyExitUsage
	}

	tmp, err := os.MkdirTemp(tmpBase, "rhg-verify-update-")
	if err != nil {
		fmt.Fprintf(stderr, "FAIL: create temp dir: %v\n", err)
		return verifyExitFail
	}
	defer func() {
		if err := os.RemoveAll(tmp); err != nil {
			fmt.Fprintf(stderr, "warning: remove temp dir %s: %v\n", tmp, err)
		}
	}()

	if _, err := stage(zipPath, tmp, tag, newVerifier(requirement)); err != nil {
		fmt.Fprintf(stderr, "FAIL: %s: %v\n", zipPath, err)
		return verifyExitFail
	}
	fmt.Fprintf(stdout, "OK: %s verified for %s\n", zipPath, tag)
	return verifyExitOK
}

// parseVerifyZipArgs accepts exactly `<zip> <tag>` or
// `<zip> <tag> --requirement <req>`, with a non-empty zip path and
// requirement and a tag that parses as a version.
func parseVerifyZipArgs(args []string) (zipPath, tag, requirement string, err error) {
	switch {
	case len(args) == 2:
		requirement = PinnedRequirement
	case len(args) == 4 && args[2] == "--requirement":
		requirement = args[3]
		if requirement == "" {
			return "", "", "", errors.New("--requirement must not be empty")
		}
	default:
		return "", "", "", errors.New("wrong arguments")
	}
	zipPath, tag = args[0], args[1]
	if zipPath == "" {
		return "", "", "", errors.New("zip path must not be empty")
	}
	if _, ok := normalizeVersion(tag); !ok {
		return "", "", "", fmt.Errorf("invalid tag %q (want vX.Y.Z)", tag)
	}
	return zipPath, tag, requirement, nil
}

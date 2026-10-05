package update

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

// downloadTimeout bounds the whole download, body included (http.Client.Timeout
// covers reading the body), so it must be far longer than checkTimeout.
const downloadTimeout = 10 * time.Minute

// maxDownloadBytes caps the downloaded archive size. A var so tests can lower it.
var maxDownloadBytes int64 = 100 << 20

// downloadClient is the HTTP client for asset downloads. A var so tests can
// substitute an httptest TLS server's client (downloads require https).
var downloadClient = &http.Client{Timeout: downloadTimeout, CheckRedirect: core.SafeRedirect}

// download fetches the https URL rawURL into destDir and returns the path of
// the completed archive, <destDir>/<ver>.zip, where <ver> is the canonical
// form of version (see normalizeVersion).
//
// The body is streamed to <destDir>/<ver>.zip.partial and renamed into place
// only once fully received and within maxDownloadBytes; on any failure the
// partial file is removed. destDir is created (0o700) if missing. download
// never deletes the completed archive — that is the caller's responsibility.
func download(ctx context.Context, rawURL, destDir, version string) (string, error) {
	if !isHTTPSURL(rawURL) {
		return "", errors.New("download URL must be an absolute https URL")
	}
	ver, ok := normalizeVersion(version)
	if !ok {
		return "", fmt.Errorf("invalid version %q", version)
	}
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return "", fmt.Errorf("create download directory: %w", err)
	}

	finalPath := filepath.Join(destDir, ver+zipSuffix)
	partialPath := finalPath + partialSuffix

	if err := fetchTo(ctx, rawURL, partialPath); err != nil {
		os.Remove(partialPath)
		return "", err
	}
	if err := os.Rename(partialPath, finalPath); err != nil {
		os.Remove(partialPath)
		return "", fmt.Errorf("finalize download: %w", err)
	}
	return finalPath, nil
}

// fetchTo streams rawURL into a freshly truncated file at path, enforcing
// maxDownloadBytes. The caller removes path on error.
func fetchTo(ctx context.Context, rawURL, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("build download request: %w", err)
	}
	resp, err := downloadClient.Do(req)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: unexpected HTTP status %d", resp.StatusCode)
	}
	if resp.ContentLength > maxDownloadBytes {
		return fmt.Errorf("download exceeds %d bytes", maxDownloadBytes)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create download file: %w", err)
	}
	// Read one byte past the cap so an oversized body is detected rather
	// than silently truncated.
	n, copyErr := io.Copy(f, io.LimitReader(resp.Body, maxDownloadBytes+1))
	closeErr := f.Close()
	if copyErr != nil {
		return fmt.Errorf("download: %w", copyErr)
	}
	if n > maxDownloadBytes {
		return fmt.Errorf("download exceeds %d bytes", maxDownloadBytes)
	}
	if closeErr != nil {
		return fmt.Errorf("write download file: %w", closeErr)
	}
	return nil
}

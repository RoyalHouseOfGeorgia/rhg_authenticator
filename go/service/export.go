package service

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
)

// exportFileMode is the mode of a saved file: what a Fyne save dialog's
// os.Create gives under the usual 022 umask.
const exportFileMode = 0o644

// ErrProtectedPath is returned by every save (QR code, bulk results, log
// exports) when the chosen file's folder is the app's data folder, where its
// logs live.
var ErrProtectedPath = errors.New("Choose a folder outside the app's data folder.")

// errNotAbsolute is returned by every save when the path isn't absolute.
var errNotAbsolute = errors.New("Choose a file to save to.")

// Fixed user-facing texts for a failed save.
const (
	msgSavePermission = "You don't have permission to save there. Choose another folder."
	msgSaveReadOnly   = "That location is read-only. Choose another folder."
	msgSaveNoFolder   = "That folder doesn't exist. Choose another folder."
	msgSaveFailed     = "Could not save the file."
)

// saver saves files the operator chose, refusing the data folder dataDir and
// logging to logger. It needs no App, so the error log can be exported before
// one exists.
type saver struct {
	dataDir string
	logger  *debuglog.Logger
}

// saver returns the App's saver.
func (a *App) saver() saver { return saver{dataDir: a.dataDir, logger: a.logger} }

// ExportIssuanceLog saves the raw issuance log to path, for a native save
// panel that leaves the target untouched until the save. It returns
// ErrNothingToExport when no credential has been logged; other errors are
// as for every save (see saveUserFile).
func (a *App) ExportIssuanceLog(path string) error {
	return a.saver().exportTo(path, a.IssuanceLogExport)
}

// ExportErrorLog saves logger's diagnostic log to path, for a native save
// panel that leaves the target untouched until the save. It needs no App, so
// a host can export while its App is still being created or after it failed
// to start. dataDir is the data folder the log lives in, which path may not
// be in. Errors are as for every save (see saveUserFile).
func ExportErrorLog(dataDir string, logger *debuglog.Logger, path string) error {
	s := saver{dataDir: dataDir, logger: logger}
	return s.exportTo(path, s.errorLog)
}

// errorLog returns the diagnostic log. Errors are logged and their text is
// user-facing.
func (s saver) errorLog() ([]byte, error) {
	data, err := os.ReadFile(s.logger.Path())
	if err != nil {
		s.logger.Logf("errorlog: failed to read log for export: %s", core.SanitizeForLog(err.Error()))
		return nil, userErr("Could not read the error log.", err)
	}
	return data, nil
}

// exportTo checks path, reads the export with read and saves it to path. The
// path is checked first, so a refused target never sees a read error.
func (s saver) exportTo(path string, read func() ([]byte, error)) error {
	if err := s.checkSavePath(path); err != nil {
		return err
	}
	data, err := read()
	if err != nil {
		return err
	}
	return s.saveUserFile(path, data)
}

// saveUserFile writes data to path, a file the operator chose, through a
// temporary file in the same folder, so a failed save never leaves a partial
// file. It returns errNotAbsolute for a relative path, ErrProtectedPath for a
// file whose folder is the data folder, and otherwise a logged error with a
// fixed user-facing text.
func (s saver) saveUserFile(path string, data []byte) error {
	if err := s.checkSavePath(path); err != nil {
		return err
	}
	if err := writeFileAtomic(path, data); err != nil {
		s.logger.Logf("save failed: %s", core.SanitizeForLog(err.Error()))
		return userErr(saveErrorMessage(err), err)
	}
	return nil
}

// checkSavePath refuses a relative path and, logging it, a protected one.
func (s saver) checkSavePath(path string) error {
	if !filepath.IsAbs(path) {
		return errNotAbsolute
	}
	if s.isProtected(path) {
		s.logger.Logf("save refused in the data folder: %s", core.SanitizeForLog(path))
		return ErrProtectedPath
	}
	return nil
}

// isProtected reports whether path's folder is the data folder, where the
// issuance log, its backups and the diagnostic log live, whether or not path
// exists yet. Comparing with os.SameFile catches case variants, symlinked
// folders and ".." components. A symlink elsewhere that points at a log is
// not protected: the save's rename replaces the link, never the log.
func (s saver) isProtected(path string) bool {
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return false
	}
	data, err := os.Stat(s.dataDir)
	return err == nil && os.SameFile(dir, data)
}

// writeFileAtomic writes data to a temporary file in path's folder and
// renames it onto path. The temporary file is removed on any failure. Its
// name is short and fixed, so a target name near the filesystem's length
// limit still saves.
func writeFileAtomic(path string, data []byte) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".rhg-save-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(exportFileMode)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// saveErrorMessage maps a failed save to its fixed user-facing text.
func saveErrorMessage(err error) string {
	for _, ro := range readOnlyErrors {
		if errors.Is(err, ro) {
			return msgSaveReadOnly
		}
	}
	switch {
	case errors.Is(err, fs.ErrPermission):
		return msgSavePermission
	case errors.Is(err, fs.ErrNotExist):
		return msgSaveNoFolder
	default:
		return msgSaveFailed
	}
}

// readOnlyErrors are the errors a write to a read-only filesystem returns on
// unix; Windows adds ERROR_WRITE_PROTECT in export_windows.go.
var readOnlyErrors = append([]error{syscall.EROFS}, platformReadOnlyErrors...)

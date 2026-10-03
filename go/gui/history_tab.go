package gui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	stdlog "log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
	"github.com/royalhouseofgeorgia/rhg-authenticator/log"
	"github.com/royalhouseofgeorgia/rhg-authenticator/registry"
	"github.com/royalhouseofgeorgia/rhg-authenticator/safego"
)

// maxHonorDisplay is the maximum number of characters to show for the honor
// field in the history list.
const maxHonorDisplay = 50

// revocationTimeout is the deadline for the revocation goroutine.
const revocationTimeout = 180 * time.Second

// revocationCacheUnavailableMsg is the error shown when the revocation list
// has not loaded at revoke time.
const revocationCacheUnavailableMsg = "Revocation data not loaded. Try refreshing."

// shouldEnableRevoke reports whether the Revoke button should be enabled: a
// usable GitHub client exists, the revocation list has loaded, a record is
// selected, and that record is not already revoked. cacheReady keeps the button
// state in sync with the OnTapped precondition (which needs the revocation list
// loaded) — without it, selecting a row after a failed fetch would enable a
// button whose tap dead-ends in the "Revocation unavailable" error. Pure and
// nil-safe — callable with selected == nil (the login-state refresh case).
func shouldEnableRevoke(clientNil, cacheReady bool, selected *log.IssuanceRecord, revoked map[string]bool) bool {
	return !clientNil && cacheReady && selected != nil && !revoked[strings.ToLower(selected.PayloadSHA256)]
}

// NewHistoryTab creates the issuance history tab UI. It returns the tab content
// and a refreshLoginState closure that re-syncs the login-dependent UI (the
// sign-in button's visibility and the Revoke button's enablement); the caller
// invokes it whenever GitHub login state changes. loginFn is invoked by the
// "Connect to GitHub" button (logged out, or logged in but offline);
// onUnauthorized is invoked after the operator dismisses the "Session Expired"
// dialog shown when a revocation PR fails with HTTP 401. Both run on the Fyne
// main thread.
func NewHistoryTab(logPath string, revocationURL string, ghClientFn func() *ghapi.Client, loginFn func(), onUnauthorized func(), window fyne.Window) (*fyne.Container, func()) {
	var allRecords []log.IssuanceRecord
	var filtered []log.IssuanceRecord
	var selectedRecord *log.IssuanceRecord
	var revokedHashes map[string]bool // key = lowercase payload_sha256
	var revocationsLoaded bool        // revocation list fetched; gates Revoke
	var revokeInFlight bool           // a revocation PR is being created; keeps Revoke disabled

	// logPath lives in the data dir, alongside the debug log.
	debugLogPath := filepath.Join(filepath.Dir(logPath), debuglog.FileName)

	searchEntry := widget.NewEntry()
	searchEntry.SetPlaceHolder("Search by recipient...")

	revocationStatus := widget.NewLabel("")

	list := widget.NewList(
		func() int {
			return len(filtered)
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("template")
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			label, ok := obj.(*widget.Label)
			if !ok {
				return
			}
			if id < 0 || id >= len(filtered) {
				return
			}
			rec := filtered[id]
			label.SetText(formatRecordSummaryWithRevocation(rec, revokedHashes))
		},
	)

	revokeButton := widget.NewButton("Revoke", nil)
	revokeButton.Disable() // Disabled until an entry is selected.

	// updateRevokeButton applies the shared enable rule. clientNil is passed in
	// so each caller reads ghClientFn() exactly once (GitHubClient allocates).
	updateRevokeButton := func(clientNil bool) {
		if !revokeInFlight && shouldEnableRevoke(clientNil, revocationsLoaded, selectedRecord, revokedHashes) {
			revokeButton.Enable()
		} else {
			revokeButton.Disable()
		}
	}

	list.OnSelected = func(id widget.ListItemID) {
		if id < 0 || id >= len(filtered) {
			selectedRecord = nil
			revokeButton.Disable()
			return
		}
		rec := filtered[id]
		selectedRecord = &rec

		// Enable/disable revoke button based on login + revocation status.
		updateRevokeButton(ghClientFn() == nil)

		// Show detail dialog (existing behavior).
		detail := formatRecordDetail(rec)
		dialog.ShowInformation("Issuance Record", detail, window)
	}

	// markRevoked records hash as revoked locally (submitted, already revoked or
	// pending) and leaves Revoke disabled. UI thread only.
	markRevoked := func(hash string) {
		revokeInFlight = false
		if revokedHashes == nil {
			revokedHashes = make(map[string]bool)
		}
		revokedHashes[strings.ToLower(hash)] = true
		list.Refresh()
		selectedRecord = nil
		revokeButton.Disable()
	}

	// Wire up the revoke button's action (defined after list so we can reference filtered).
	revokeButton.OnTapped = func() {
		if selectedRecord == nil {
			return
		}
		client := ghClientFn() // capture once on main thread, BEFORE ShowConfirm
		if client == nil {
			dialog.ShowError(fmt.Errorf("not logged in to GitHub"), window)
			return
		}
		rec := *selectedRecord // local copy on main thread

		// Check if already revoked.
		if revokedHashes[strings.ToLower(rec.PayloadSHA256)] {
			dialog.ShowInformation("Already Revoked", ghapi.UserMessage(ghapi.ErrAlreadyRevoked), window)
			return
		}

		if !revocationsLoaded {
			dialog.ShowError(fmt.Errorf("%s", revocationCacheUnavailableMsg), window)
			return
		}

		// Confirmation dialog.
		msg := fmt.Sprintf("Revoke credential for %s dated %s?\n\nThis cannot be undone.", rec.Recipient, core.FormatDateDisplay(rec.Date))
		dialog.ShowConfirm("Confirm Revocation", msg, func(confirmed bool) {
			if !confirmed {
				return
			}
			// Prevent a second tap from opening a duplicate PR while this one is
			// in flight (updateRevokeButton honours the flag); re-enabled on
			// failure, left disabled once the hash is revoked or pending.
			revokeInFlight = true
			revokeButton.Disable()

			safego.Go(func() {
				ctx, cancel := context.WithTimeout(context.Background(), revocationTimeout)
				defer cancel()

				// ghapi builds the new revocations.json from upstream main, so
				// revocations merged since the last fetch are never dropped.
				pr, err := client.CreateRevocationPR(ctx, rec.PayloadSHA256, time.Now().UTC().Format("2006-01-02"))
				if err != nil {
					unauthorized, infoTitle, msg := revokeFailureAction(err)
					if infoTitle != "" {
						// Nothing to submit: the hash is already revoked upstream
						// or awaiting review, so mark it locally like a success.
						stdlog.Printf("info: revocation not submitted: %s", core.SanitizeForLog(err.Error()))
						fyne.Do(func() {
							markRevoked(rec.PayloadSHA256)
							dialog.ShowInformation(infoTitle, msg, window)
						})
						return
					}
					stdlog.Printf("error: revocation PR failed: %s", core.SanitizeForLog(err.Error()))
					fyne.Do(func() {
						revokeInFlight = false
						updateRevokeButton(ghClientFn() == nil)
						if unauthorized {
							d := dialog.NewInformation("Session Expired", msg, window)
							d.SetOnClosed(onUnauthorized)
							d.Show()
							return
						}
						ShowErrorWithLogExport("Revocation Failed", msg, debugLogPath, window)
					})
					return
				}

				fyne.Do(func() {
					markRevoked(rec.PayloadSHA256)
					dialog.ShowInformation("Revocation Submitted", fmt.Sprintf("Pull request #%d created:\n%s\n\nIf several revocation PRs are open, merge them one at a time.", pr.Number, pr.HTMLURL), window)
				})
			})
		}, window)
	}

	fetchRevocations := func() {
		safego.Go(func() {
			revList, err := registry.FetchRevocationList(revocationURL)
			if err != nil {
				stdlog.Printf("history: failed to fetch revocation list: %s", core.SanitizeForLog(err.Error()))
				fyne.Do(func() {
					revokeButton.Disable()
					revocationStatus.Importance = widget.WarningImportance
					revocationStatus.SetText("Revocation unavailable")
				})
				return
			}
			newHashes := core.BuildRevocationSet(revList)
			// Update UI on the main thread.
			fyne.Do(func() {
				revokedHashes = newHashes
				revocationsLoaded = true
				revocationStatus.Importance = widget.MediumImportance
				revocationStatus.SetText("")
				list.Refresh()
				// Re-evaluate revoke button based on current selection.
				updateRevokeButton(ghClientFn() == nil)
			})
		})
	}

	loadRecords := func() {
		records, err := log.ReadLog(logPath)
		if err != nil {
			stdlog.Printf("history: failed to read log: %s", core.SanitizeForLog(err.Error()))
			dialog.ShowError(fmt.Errorf("unable to load history"), window)
			return
		}
		allRecords = records
		filtered = filterRecords(allRecords, searchEntry.Text)
		list.UnselectAll()
		selectedRecord = nil
		revokeButton.Disable()
		list.Refresh()
	}

	searchEntry.OnChanged = func(query string) {
		filtered = filterRecords(allRecords, query)
		list.UnselectAll()
		selectedRecord = nil
		revokeButton.Disable()
		list.Refresh()
	}

	refreshButton := widget.NewButton("Refresh", func() {
		loadRecords()
		fetchRevocations()
	})

	// signInButton lets the operator (re)establish a GitHub session without
	// leaving the History tab: it starts device login when logged out, or
	// retries session restore when logged in but offline. Shown only when no
	// usable client exists; login is owned by the Registry tab (the single
	// source of login-state truth).
	signInButton := widget.NewButton("Connect to GitHub", func() { loginFn() })

	// refreshLoginState re-syncs the login-dependent UI. Reads ghClientFn() once
	// and reuses the result for both the button visibility and the Revoke gate.
	refreshLoginState := func() {
		clientNil := ghClientFn() == nil
		if clientNil {
			signInButton.Show()
		} else {
			signInButton.Hide()
		}
		updateRevokeButton(clientNil)
	}

	exportButton := widget.NewButton("Export Issuance Log…", func() {
		onIssuanceExportTapped(logPath, window)
	})

	dedupButton := widget.NewButton("Remove Duplicates…", func() {
		onRemoveDuplicatesTapped(logPath, debugLogPath, loadRecords, window)
	})

	// Initial load.
	loadRecords()
	fetchRevocations()

	buttonBar := container.NewHBox(refreshButton, signInButton, revokeButton, exportButton, dedupButton, revocationStatus)
	topBar := container.NewBorder(nil, nil, nil, buttonBar, searchEntry)
	return container.NewBorder(topBar, nil, nil, nil, list), refreshLoginState
}

// revokeFailureAction classifies a revocation-PR error: a 401 means the
// session expired (caller restarts login); an already-revoked or pending
// revocation is not a failure and returns a non-empty infoTitle (caller shows
// an information dialog and marks the record revoked); anything else maps to
// a user-facing message.
func revokeFailureAction(err error) (unauthorized bool, infoTitle, msg string) {
	if ghapi.IsUnauthorized(err) {
		return true, "", "Your GitHub session expired. Please log in again."
	}
	if errors.Is(err, ghapi.ErrAlreadyRevoked) {
		return false, "Already Revoked", ghapi.UserMessage(err)
	}
	if errors.Is(err, ghapi.ErrRevocationPending) {
		return false, "Revocation Pending", ghapi.UserMessage(err)
	}
	return false, "", ghapi.UserMessage(err)
}

// filterRecords returns records matching the query (case-insensitive substring
// match on recipient), in reverse chronological order (newest first).
func filterRecords(records []log.IssuanceRecord, query string) []log.IssuanceRecord {
	lowerQuery := strings.ToLower(strings.TrimSpace(query))
	n := len(records)
	result := make([]log.IssuanceRecord, 0, n)

	// Iterate in reverse for newest-first ordering.
	for i := n - 1; i >= 0; i-- {
		rec := records[i]
		if lowerQuery == "" || strings.Contains(strings.ToLower(rec.Recipient), lowerQuery) {
			result = append(result, rec)
		}
	}
	return result
}

// formatRecordSummary returns a one-line summary for the history list.
func formatRecordSummary(rec log.IssuanceRecord) string {
	return fmt.Sprintf("%s | %s | %s", core.FormatDateDisplay(rec.Date), rec.Recipient, truncateRunes(rec.Honor, maxHonorDisplay))
}

// formatRecordSummaryWithRevocation wraps formatRecordSummary, prefixing
// "[REVOKED] " when the record's payload hash appears in the revoked set.
func formatRecordSummaryWithRevocation(rec log.IssuanceRecord, revokedHashes map[string]bool) string {
	summary := formatRecordSummary(rec)
	if revokedHashes[strings.ToLower(rec.PayloadSHA256)] {
		return "[REVOKED] " + summary
	}
	return summary
}

// formatRecordDetail returns a multi-line detail string for the record dialog.
func formatRecordDetail(rec log.IssuanceRecord) string {
	return fmt.Sprintf(
		"Timestamp: %s\nRecipient: %s\nHonor: %s\nDetail: %s\nDate: %s\nPayload SHA-256: %s\nSignature: %s",
		rec.Timestamp, rec.Recipient, rec.Honor, rec.Detail, core.FormatDateDisplay(rec.Date),
		rec.PayloadSHA256, rec.SignatureB64URL,
	)
}

// onIssuanceExportTapped hands the raw log file to a non-technical operator
// via a save dialog. The log is read before the dialog opens because Fyne
// truncates the destination before the save callback runs; that keeps the log
// intact if it is picked as the destination, as long as the write succeeds.
func onIssuanceExportTapped(logPath string, window fyne.Window) {
	data, readErr := os.ReadFile(logPath)
	if errors.Is(readErr, fs.ErrNotExist) {
		showNothingToExport(window)
		return
	}
	if readErr != nil {
		stdlog.Printf("history: failed to read log for export: %s", core.SanitizeForLog(readErr.Error()))
		dialog.ShowError(errors.New("could not read the issuance log"), window)
		return
	}
	if !hasRecords(data) {
		showNothingToExport(window)
		return
	}
	saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
		onIssuanceExportChosen(data, window, writer, err)
	}, window)
	saveDialog.SetFileName(time.Now().Format("rhg-issuances-2006-01-02.json"))
	saveDialog.SetFilter(storage.NewExtensionFileFilter([]string{".json"}))
	if desktop, ok := desktopDir(); ok {
		saveDialog.SetLocation(desktop)
	}
	saveDialog.Show()
}

// onRemoveDuplicatesTapped previews the duplicate count read-only, then asks
// for confirmation before RemoveDuplicates re-reads and rewrites the log
// (backing it up first). onRemoved reloads the list after a rewrite.
func onRemoveDuplicatesTapped(logPath, debugLogPath string, onRemoved func(), window fyne.Window) {
	records, err := log.ReadLog(logPath)
	if err != nil {
		stdlog.Printf("history: failed to read log for dedup: %s", core.SanitizeForLog(err.Error()))
		ShowErrorWithLogExport("Remove Duplicates Failed", "Could not read the issuance log.", debugLogPath, window)
		return
	}
	_, n := log.Dedupe(records)
	if n == 0 {
		showNoDuplicates(window)
		return
	}
	msg := fmt.Sprintf("Found %d duplicate entries. The earliest valid entry of each credential is kept and later copies are removed. A backup of the current log is saved first. Continue?", n)
	d := dialog.NewConfirm("Remove Duplicates", msg, func(ok bool) {
		if !ok {
			return
		}
		removed, backup, err := log.RemoveDuplicates(logPath)
		if err != nil {
			stdlog.Printf("history: remove duplicates failed: %s", core.SanitizeForLog(err.Error()))
			ShowErrorWithLogExport("Remove Duplicates Failed", "Could not remove duplicates. The issuance log was not changed.", debugLogPath, window)
			return
		}
		if removed == 0 {
			// The log changed between the preview and the confirm.
			showNoDuplicates(window)
			return
		}
		dialog.ShowInformation("Duplicates Removed", fmt.Sprintf("Removed %d entries. Backup saved to %s.", removed, backup), window)
		onRemoved()
	}, window)
	d.SetConfirmText("Remove Entries")
	d.SetDismissText("Cancel")
	d.Show()
}

func showNoDuplicates(window fyne.Window) {
	dialog.ShowInformation("No Duplicates", "The issuance log has no duplicate entries.", window)
}

func showNothingToExport(window fyne.Window) {
	dialog.ShowInformation("Nothing to Export", "No credentials have been signed on this computer yet.", window)
}

// onIssuanceExportChosen is the export save-dialog callback: it writes data
// (the log bytes read at click time) through the writer Fyne opened.
func onIssuanceExportChosen(data []byte, window fyne.Window, writer fyne.URIWriteCloser, err error) {
	// Fyne reports an uncreatable destination as a writer plus a non-nil
	// error, so err must be checked before writer.
	if err != nil {
		stdlog.Printf("history: export save failed: %s", core.SanitizeForLog(err.Error()))
		showSaveError(window, "issuance log")
		return
	}
	if writer == nil {
		return // cancelled
	}
	_, werr := writer.Write(data)
	cerr := writer.Close()
	if werr != nil || cerr != nil {
		stdlog.Printf("history: export write failed: %s", core.SanitizeForLog(errors.Join(werr, cerr).Error()))
		showSaveError(window, "issuance log")
		return
	}
	dialog.ShowInformation("Issuance Log Exported",
		"Saved to:\n"+filepath.FromSlash(writer.URI().Path())+"\n\nYou can attach this file to an email.", window)
}

// showSaveError reports a failed save of what (e.g. "issuance log") and points
// macOS users at the Files and Folders permission, the usual cause of a failed
// save to the Desktop.
func showSaveError(window fyne.Window, what string) {
	dialog.ShowError(errors.New("could not save the "+what+" — on a Mac, check System Settings → Privacy & Security → Files and Folders"), window)
}

// hasRecords reports whether a log file's contents hold at least one record.
// Unparseable contents count as records so a corrupt log can still be
// exported for inspection.
func hasRecords(data []byte) bool {
	if len(bytes.TrimSpace(data)) == 0 {
		return false
	}
	var records []json.RawMessage
	if err := json.Unmarshal(data, &records); err != nil {
		return true
	}
	return len(records) > 0
}

// desktopDir returns the user's Desktop folder as a dialog start location.
func desktopDir() (fyne.ListableURI, bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, false
	}
	desktop, err := storage.ListerForURI(storage.NewFileURI(filepath.Join(home, "Desktop")))
	if err != nil {
		return nil, false
	}
	return desktop, true
}

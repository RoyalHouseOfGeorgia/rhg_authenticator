package gui

import (
	"context"
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
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
)

// revocationTimeout is the deadline for the revocation goroutine.
const revocationTimeout = 180 * time.Second

// revocationCacheUnavailableMsg is the error shown when the revocation list
// has not loaded at revoke time.
const revocationCacheUnavailableMsg = "Revocation data not loaded. Try refreshing."

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
			label.SetText(service.FormatRecordSummaryWithRevocation(rec, revokedHashes))
		},
	)

	revokeButton := widget.NewButton("Revoke", nil)
	revokeButton.Disable() // Disabled until an entry is selected.

	// updateRevokeButton applies the shared enable rule. clientNil is passed in
	// so each caller reads ghClientFn() exactly once (GitHubClient allocates).
	updateRevokeButton := func(clientNil bool) {
		if !revokeInFlight && service.ShouldEnableRevoke(clientNil, revocationsLoaded, selectedRecord, revokedHashes) {
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
		detail := service.FormatRecordDetail(rec)
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
					unauthorized, infoTitle, msg := service.RevokeFailureAction(err)
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
		filtered = service.FilterRecords(allRecords, searchEntry.Text)
		list.UnselectAll()
		selectedRecord = nil
		revokeButton.Disable()
		list.Refresh()
	}

	searchEntry.OnChanged = func(query string) {
		filtered = service.FilterRecords(allRecords, query)
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
	if !service.HasRecords(data) {
		showNothingToExport(window)
		return
	}
	saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
		onIssuanceExportChosen(data, window, writer, err)
	}, window)
	saveDialog.SetFileName(time.Now().Format("rhg-issuances-2006-01-02.json"))
	saveDialog.SetFilter(storage.NewExtensionFileFilter([]string{".json"}))
	setDialogLocation(saveDialog)
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
// save to a protected folder (Desktop, Documents, Downloads).
func showSaveError(window fyne.Window, what string) {
	dialog.ShowError(errors.New("could not save the "+what+" — on a Mac, check System Settings → Privacy & Security → Files and Folders"), window)
}

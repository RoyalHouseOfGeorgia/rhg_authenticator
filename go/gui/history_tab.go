package gui

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
	"github.com/royalhouseofgeorgia/rhg-authenticator/log"
	"github.com/royalhouseofgeorgia/rhg-authenticator/registry"
)

// maxHonorDisplay is the maximum number of characters to show for the honor
// field in the history list.
const maxHonorDisplay = 50

// revocationTimeout is the deadline for the revocation goroutine.
const revocationTimeout = 180 * time.Second

// revocationCacheUnavailableMsg is the error shown when the cached revocation
// list is nil at revoke time.
const revocationCacheUnavailableMsg = "Revocation data not loaded. Try refreshing."

// NewHistoryTab creates the issuance history tab UI.
func NewHistoryTab(logPath string, revocationURL string, ghClient *ghapi.Client, window fyne.Window) *fyne.Container {
	canRevoke := ghClient != nil

	var allRecords []log.IssuanceRecord
	var filtered []log.IssuanceRecord
	var selectedRecord *log.IssuanceRecord
	var revokedHashes map[string]bool // key = lowercase payload_sha256
	var cachedRevocationList *core.RevocationList

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

	list.OnSelected = func(id widget.ListItemID) {
		if id < 0 || id >= len(filtered) {
			selectedRecord = nil
			revokeButton.Disable()
			return
		}
		rec := filtered[id]
		selectedRecord = &rec

		// Enable/disable revoke button based on revocation status.
		if !canRevoke || revokedHashes[strings.ToLower(rec.PayloadSHA256)] {
			revokeButton.Disable()
		} else {
			revokeButton.Enable()
		}

		// Show detail dialog (existing behavior).
		detail := formatRecordDetail(rec)
		dialog.ShowInformation("Issuance Record", detail, window)
	}

	// Wire up the revoke button's action (defined after list so we can reference filtered).
	revokeButton.OnTapped = func() {
		if selectedRecord == nil {
			return
		}
		rec := *selectedRecord // local copy on main thread
		cached := cachedRevocationList

		// Check if already revoked.
		if revokedHashes[strings.ToLower(rec.PayloadSHA256)] {
			dialog.ShowInformation("Already Revoked", "This credential has already been revoked.", window)
			return
		}

		if cached == nil {
			dialog.ShowError(fmt.Errorf("%s", revocationCacheUnavailableMsg), window)
			return
		}

		if ghClient == nil {
			dialog.ShowError(fmt.Errorf("not logged in to GitHub"), window)
			return
		}

		// Confirmation dialog.
		msg := fmt.Sprintf("Revoke credential for %s dated %s?\n\nThis cannot be undone.", rec.Recipient, core.FormatDateDisplay(rec.Date))
		dialog.ShowConfirm("Confirm Revocation", msg, func(confirmed bool) {
			if !confirmed {
				return
			}

			// Build updated revocation list.
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), revocationTimeout)
				defer cancel()

				// Deep-copy cached revocation list before mutating.
				entries := make([]core.RevocationEntry, len(cached.Revocations), len(cached.Revocations)+1)
				copy(entries, cached.Revocations)
				today := time.Now().UTC().Format("2006-01-02")
				entries = append(entries, core.RevocationEntry{
					Hash:      strings.ToLower(rec.PayloadSHA256),
					RevokedOn: today,
				})
				updatedList := &core.RevocationList{Revocations: entries}

				// Marshal.
				content, err := json.MarshalIndent(updatedList, "", "  ")
				if err != nil {
					fyne.Do(func() {
						dialog.ShowError(fmt.Errorf("failed to prepare revocation data"), window)
					})
					return
				}
				content = append(content, '\n')

				pr, err := ghClient.CreateRevocationPR(ctx, content, rec.PayloadSHA256)
				if err != nil {
					fyne.Do(func() {
						dialog.ShowError(fmt.Errorf("failed to submit revocation"), window)
					})
					return
				}

				fyne.Do(func() {
					dialog.ShowInformation("Revocation Submitted", fmt.Sprintf("Pull request #%d created:\n%s", pr.Number, pr.HTMLURL), window)
					// Update local state.
					if revokedHashes == nil {
						revokedHashes = make(map[string]bool)
					}
					revokedHashes[strings.ToLower(rec.PayloadSHA256)] = true
					list.Refresh()
					selectedRecord = nil
					revokeButton.Disable()
				})
			}()
		}, window)
	}

	fetchRevocations := func() {
		go func() {
			revList, err := registry.FetchRevocationList(revocationURL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "history: failed to fetch revocation list: %s\n", core.SanitizeForLog(err.Error()))
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
				cachedRevocationList = revList
				revocationStatus.Importance = widget.MediumImportance
				revocationStatus.SetText("")
				list.Refresh()
				// Re-evaluate revoke button based on current selection.
				if canRevoke && selectedRecord != nil && !revokedHashes[strings.ToLower(selectedRecord.PayloadSHA256)] {
					revokeButton.Enable()
				} else {
					revokeButton.Disable()
				}
			})
		}()
	}

	loadRecords := func() {
		records, err := log.ReadLog(logPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "history: failed to read log: %v\n", err)
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

	// Initial load.
	loadRecords()
	fetchRevocations()

	buttonBar := container.NewHBox(refreshButton, revokeButton, revocationStatus)
	topBar := container.NewBorder(nil, nil, nil, buttonBar, searchEntry)
	return container.NewBorder(topBar, nil, nil, nil, list)
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

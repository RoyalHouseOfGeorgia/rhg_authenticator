package gui

import (
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/log"
)

// maxHonorDisplay is the maximum number of characters to show for the honor
// field in the history list.
const maxHonorDisplay = 50

// NewHistoryTab creates the issuance history tab UI.
func NewHistoryTab(logPath string, window fyne.Window) *fyne.Container {
	var allRecords []log.IssuanceRecord
	var filtered []log.IssuanceRecord

	searchEntry := widget.NewEntry()
	searchEntry.SetPlaceHolder("Search by recipient...")

	list := widget.NewList(
		func() int {
			return len(filtered)
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("template")
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			label := obj.(*widget.Label)
			if id < 0 || id >= len(filtered) {
				return
			}
			rec := filtered[id]
			label.SetText(formatRecordSummary(rec))
		},
	)

	list.OnSelected = func(id widget.ListItemID) {
		if id < 0 || id >= len(filtered) {
			return
		}
		rec := filtered[id]
		detail := formatRecordDetail(rec)
		dialog.ShowInformation("Issuance Record", detail, window)
		list.UnselectAll()
	}

	loadRecords := func() {
		records, err := log.ReadLog(logPath)
		if err != nil {
			dialog.ShowError(fmt.Errorf("Failed to read log: %w", err), window)
			return
		}
		allRecords = records
		filtered = filterRecords(allRecords, searchEntry.Text)
		list.Refresh()
	}

	searchEntry.OnChanged = func(query string) {
		filtered = filterRecords(allRecords, query)
		list.Refresh()
	}

	refreshButton := widget.NewButton("Refresh", func() {
		loadRecords()
	})

	// Initial load.
	loadRecords()

	topBar := container.NewBorder(nil, nil, nil, refreshButton, searchEntry)
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

// truncateHonor truncates the honor string to maxLen characters, appending
// an ellipsis if truncated.
// Note: truncates at rune boundary, not grapheme cluster. Combining marks may be split. Acceptable for UI display.
func truncateHonor(honor string, maxLen int) string {
	runes := []rune(honor)
	if len(runes) <= maxLen {
		return honor
	}
	return string(runes[:maxLen]) + "..."
}

// formatRecordSummary returns a one-line summary for the history list.
func formatRecordSummary(rec log.IssuanceRecord) string {
	return fmt.Sprintf("%s | %s | %s", rec.Date, rec.Recipient, truncateHonor(rec.Honor, maxHonorDisplay))
}

// formatRecordDetail returns a multi-line detail string for the record dialog.
func formatRecordDetail(rec log.IssuanceRecord) string {
	return fmt.Sprintf(
		"Timestamp: %s\nRecipient: %s\nHonor: %s\nDetail: %s\nDate: %s\nAuthority: %s\nPayload SHA-256: %s\nSignature: %s",
		rec.Timestamp, rec.Recipient, rec.Honor, rec.Detail, rec.Date,
		rec.Authority, rec.PayloadSHA256, rec.SignatureB64URL,
	)
}

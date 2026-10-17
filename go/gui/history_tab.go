package gui

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
	"github.com/royalhouseofgeorgia/rhg-authenticator/safego"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
)

// HistoryTab is the issuance history UI on top of service.App. Its methods
// run on the Fyne main thread.
type HistoryTab struct {
	Content          fyne.CanvasObject
	svc              *service.App
	window           fyne.Window
	login            func() // starts a GitHub login (the Registry tab owns it)
	snap             service.HistorySnapshot
	selected         int  // index into snap.Rows; -1 = none
	revokeInFlight   bool // a revocation PR is being created; keeps Revoke disabled
	searchEntry      *widget.Entry
	list             *widget.List
	revokeButton     *widget.Button
	signInButton     *widget.Button
	revocationStatus *widget.Label
}

// NewHistoryTab creates the issuance history tab on svc, whose history events
// arrive through events; svc.Start loads the history. login starts a GitHub
// login: the "Connect to GitHub" button calls it, as do a revocation refused
// for want of a session and the dismissal of the "Session Expired" dialog.
// The caller calls RefreshLoginState whenever the login state changes.
func NewHistoryTab(svc *service.App, events *Events, login func(), window fyne.Window) *HistoryTab {
	h := &HistoryTab{
		svc:              svc,
		window:           window,
		login:            login,
		selected:         -1,
		searchEntry:      widget.NewEntry(),
		revocationStatus: widget.NewLabel(""),
	}
	h.searchEntry.SetPlaceHolder("Search by recipient...")
	h.searchEntry.OnChanged = func(string) { h.reload(true) }

	h.list = widget.NewList(
		func() int {
			return len(h.snap.Rows)
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("template")
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			label, ok := obj.(*widget.Label)
			if !ok {
				return
			}
			if id < 0 || id >= len(h.snap.Rows) {
				return
			}
			label.SetText(h.snap.Rows[id].Summary)
		},
	)
	h.list.OnSelected = h.rowSelected

	h.revokeButton = widget.NewButton("Revoke", h.revokeTapped)
	h.revokeButton.Disable() // Disabled until an entry is selected.

	refreshButton := widget.NewButton("Refresh", func() { safego.Go(svc.RefreshHistory) })

	// signInButton lets the operator (re)establish a GitHub session without
	// leaving the History tab. Shown only when there is no usable session.
	h.signInButton = widget.NewButton("Connect to GitHub", func() { h.login() })

	exportButton := widget.NewButton("Export Issuance Log…", func() {
		onIssuanceExportTapped(svc.IssuanceLogExport, window)
	})
	dedupButton := widget.NewButton("Remove Duplicates…", func() {
		onRemoveDuplicatesTapped(svc, window)
	})

	buttonBar := container.NewHBox(refreshButton, h.signInButton, h.revokeButton, exportButton, dedupButton, h.revocationStatus)
	topBar := container.NewBorder(nil, nil, nil, buttonBar, h.searchEntry)
	h.Content = container.NewBorder(topBar, nil, nil, nil, h.list)

	// Register first, then read state, so an event that fired before
	// registration is not missed.
	events.On(service.EventHistoryChanged, func(any) { h.historyChanged() })
	events.On(service.EventRevocationsChanged, func(any) { h.revocationsChanged() })
	h.applyAuth(svc.AuthState())
	return h
}

// RefreshLoginState re-syncs the login-dependent UI: the "Connect to GitHub"
// button's visibility and the Revoke button's enablement.
func (h *HistoryTab) RefreshLoginState() {
	h.applyAuth(h.svc.AuthState())
}

// applyAuth shows "Connect to GitHub" unless st is a usable session, then
// re-reads the history (which carries the Revoke gate).
func (h *HistoryTab) applyAuth(st service.AuthState) {
	if !st.LoggedIn || st.Offline {
		h.signInButton.Show()
	} else {
		h.signInButton.Hide()
	}
	h.reload(false)
}

// updateRevokeButton enables Revoke for a selected, unrevoked row when the
// snapshot allows revoking and no revocation is in flight.
func (h *HistoryTab) updateRevokeButton() {
	if !h.revokeInFlight && h.snap.RevokeAvailable && h.selected >= 0 && h.selected < len(h.snap.Rows) && !h.snap.Rows[h.selected].Revoked {
		h.revokeButton.Enable()
	} else {
		h.revokeButton.Disable()
	}
}

// reload re-reads the history for the current search, clearing the selection
// when resetSelection is set (the records may have changed). Otherwise the
// selected index stays valid: only a record change or a new search reorders
// the rows, and both reset it.
func (h *HistoryTab) reload(resetSelection bool) {
	h.snap = h.svc.History(h.searchEntry.Text)
	if resetSelection || h.selected >= len(h.snap.Rows) {
		h.list.UnselectAll()
		h.selected = -1
	}
	h.list.Refresh()
	h.updateRevokeButton()
}

// rowSelected stores the selection and shows the record's details.
func (h *HistoryTab) rowSelected(id widget.ListItemID) {
	if id < 0 || id >= len(h.snap.Rows) {
		h.selected = -1
		h.revokeButton.Disable()
		return
	}
	h.selected = id
	h.updateRevokeButton()
	dialog.ShowInformation("Issuance Record", service.FormatRecordDetail(h.snap.Rows[id].Record), h.window)
}

// historyChanged applies a re-read issuance log (EventHistoryChanged).
func (h *HistoryTab) historyChanged() {
	h.reload(true)
	if h.snap.LoadFailed {
		dialog.ShowError(errors.New("unable to load history"), h.window)
	}
}

// revocationsChanged applies a finished revocation-list fetch
// (EventRevocationsChanged), keeping the selection.
func (h *HistoryTab) revocationsChanged() {
	h.reload(false)
	if h.snap.RevocationsUnavailable {
		h.revokeButton.Disable()
		h.revocationStatus.Importance = widget.WarningImportance
		h.revocationStatus.SetText("Revocation unavailable")
		return
	}
	h.revocationStatus.Importance = widget.MediumImportance
	h.revocationStatus.SetText("")
}

// revokeTapped confirms and starts revoking the selected row. Revoke itself
// refuses a row that can't be revoked (no session, already revoked,
// revocation list not loaded) and revokeDone shows why.
func (h *HistoryTab) revokeTapped() {
	if h.selected < 0 || h.selected >= len(h.snap.Rows) {
		return
	}
	row := h.snap.Rows[h.selected]

	dialog.ShowConfirm("Confirm Revocation", service.RevokeConfirmText(row.Record), func(confirmed bool) {
		if !confirmed {
			return
		}
		// Prevent a second tap from opening a duplicate PR while this one is
		// in flight (updateRevokeButton honours the flag).
		h.revokeInFlight = true
		h.revokeButton.Disable()
		hash := row.Record.PayloadSHA256
		safego.Go(func() {
			res, err := h.svc.Revoke(context.Background(), hash)
			fyne.Do(func() { h.revokeDone(res, err) })
		})
	}, h.window)
}

// revokeDone shows the outcome of a Revoke.
func (h *HistoryTab) revokeDone(res service.RevokeResult, err error) {
	h.revokeInFlight = false
	switch {
	case err == nil:
		h.reload(true) // the row now reads revoked
		dialog.ShowInformation(res.Title, res.Message, h.window)
	case errors.Is(err, service.ErrBusy):
		// Unreachable from this tab (Revoke stays disabled while one runs);
		// the running revocation reports its own outcome.
		h.updateRevokeButton()
	case errors.Is(err, service.ErrNotLoggedIn):
		h.updateRevokeButton()
		h.login()
	case ghapi.IsUnauthorized(err):
		// Revoke has already logged out; log in again once the user has
		// read why.
		h.updateRevokeButton()
		title, msg := service.RevokeErrorMessage(err)
		d := dialog.NewInformation(title, msg, h.window)
		d.SetOnClosed(h.login)
		d.Show()
	default:
		h.updateRevokeButton()
		title, msg := service.RevokeErrorMessage(err)
		ShowErrorWithLogExport(title, msg, h.svc.ErrorLogExport, h.window)
	}
}

// onIssuanceExportTapped hands the raw log file to a non-technical operator
// via a save dialog. export (App.IssuanceLogExport) reads the log before the
// dialog opens because Fyne truncates the destination before the save
// callback runs; that keeps the log intact if it is picked as the
// destination, as long as the write succeeds.
func onIssuanceExportTapped(export func() ([]byte, error), window fyne.Window) {
	data, err := export()
	if errors.Is(err, service.ErrNothingToExport) {
		showNothingToExport(window)
		return
	}
	if err != nil {
		dialog.ShowError(err, window)
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
// (backing it up first); the list reloads on EventHistoryChanged.
func onRemoveDuplicatesTapped(svc *service.App, window fyne.Window) {
	n, err := svc.DuplicatePreview()
	if err != nil {
		ShowErrorWithLogExport("Remove Duplicates Failed", err.Error(), svc.ErrorLogExport, window)
		return
	}
	if n == 0 {
		showNoDuplicates(window)
		return
	}
	msg := fmt.Sprintf("Found %d duplicate entries. The earliest valid entry of each credential is kept and later copies are removed. A backup of the current log is saved first. Continue?", n)
	d := dialog.NewConfirm("Remove Duplicates", msg, func(ok bool) {
		if ok {
			removeDuplicatesConfirmed(svc, window)
		}
	}, window)
	d.SetConfirmText("Remove Entries")
	d.SetDismissText("Cancel")
	d.Show()
}

// removeDuplicatesConfirmed rewrites the log without duplicates and reports
// the outcome.
func removeDuplicatesConfirmed(svc *service.App, window fyne.Window) {
	removed, backup, err := svc.RemoveDuplicates()
	if err != nil {
		ShowErrorWithLogExport("Remove Duplicates Failed", err.Error(), svc.ErrorLogExport, window)
		return
	}
	if removed == 0 {
		// The log changed between the preview and the confirm.
		showNoDuplicates(window)
		return
	}
	dialog.ShowInformation("Duplicates Removed", fmt.Sprintf("Removed %d entries. Backup saved to %s.", removed, backup), window)
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
	if !writeExport(data, window, writer, err, "issuance log") {
		return
	}
	dialog.ShowInformation("Issuance Log Exported",
		"Saved to:\n"+filepath.FromSlash(writer.URI().Path())+"\n\nYou can attach this file to an email.", window)
}

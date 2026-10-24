package gui

import (
	"errors"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
	"github.com/royalhouseofgeorgia/rhg-authenticator/safego"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
)

// AuditTab is the registry audit UI showing the registry's GitHub commit
// history. Its methods run on the Fyne main thread.
type AuditTab struct {
	Content     fyne.CanvasObject
	svc         *service.App
	rows        []service.AuditRow
	list        *widget.List
	statusLabel *widget.Label
	refreshBtn  *widget.Button
}

// NewAuditTab creates the audit tab on svc. It fetches nothing; the caller
// calls Refresh for the first load.
func NewAuditTab(svc *service.App) *AuditTab {
	at := &AuditTab{svc: svc, statusLabel: widget.NewLabel("")}
	at.list = widget.NewList(
		func() int {
			return len(at.rows)
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("template")
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			label, ok := obj.(*widget.Label)
			if !ok {
				return
			}
			if id < 0 || id >= len(at.rows) {
				return
			}
			label.SetText(at.rows[id].Summary)
		},
	)
	at.list.OnSelected = at.rowSelected
	at.refreshBtn = widget.NewButton("Refresh", at.Refresh)

	topBar := container.NewBorder(nil, nil, nil, at.refreshBtn, at.statusLabel)
	at.Content = container.NewBorder(topBar, nil, nil, nil, at.list)
	return at
}

// Refresh fetches the registry commit history in the background.
func (at *AuditTab) Refresh() {
	at.refreshBtn.Disable()
	at.statusLabel.SetText("Fetching...")
	safego.Go(func() {
		res, err := at.svc.AuditCommits()
		fyne.Do(func() { at.auditDone(res, err) })
	})
}

// auditDone shows the outcome of an AuditCommits.
func (at *AuditTab) auditDone(res service.AuditResult, err error) {
	if errors.Is(err, service.ErrBusy) {
		return // the running fetch updates the tab
	}
	at.refreshBtn.Enable()
	if err != nil {
		at.statusLabel.SetText(err.Error())
		return
	}
	at.rows = res.Rows
	at.list.Refresh()
	at.statusLabel.SetText(res.Status)
}

// rowSelected opens the commit page and clears the selection.
func (at *AuditTab) rowSelected(id widget.ListItemID) {
	if id < 0 || id >= len(at.rows) {
		return
	}
	if parsed := ghapi.ParseGitHubURL(at.rows[id].URL); parsed != nil {
		_ = fyne.CurrentApp().OpenURL(parsed)
	}
	at.list.UnselectAll()
}

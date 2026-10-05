package main

import (
	"fmt"
	"net/url"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/update"
)

// Update banner copy. Versions are canonical "X.Y.Z" (no "v" prefix).
const (
	readyTitleFmt   = "Version %s is ready to install."
	readyDetail     = "It will also install the next time you close the app."
	restartNowText  = "Restart now"
	manualFmt       = "Version %s is available —"
	downloadText    = "Download"
	moveToAppsHint  = "To get updates automatically, move RHG Authenticator into your Applications folder."
	updatedFmt      = "Updated to version %s."
	whatsNewText    = "What's new"
	releaseURLHost  = "github.com"
	releaseURLProto = "https"
)

// githubURL parses raw and returns it only if it is an https URL on
// github.com, so banner links can never point anywhere else.
func githubURL(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != releaseURLProto || u.Host != releaseURLHost {
		return nil, false
	}
	return u, true
}

// statusObjects renders an update Status for the banner's status slot.
// restart is the "Restart now" action. It returns nil when nothing is shown:
// Idle, an unknown State, or ManualOnly without a valid release link.
func statusObjects(s update.Status, restart func()) []fyne.CanvasObject {
	switch s.State {
	case update.StateReady:
		title := widget.NewLabelWithStyle(fmt.Sprintf(readyTitleFmt, s.Version), fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
		btn := widget.NewButton(restartNowText, restart)
		btn.Importance = widget.HighImportance
		return []fyne.CanvasObject{
			container.NewBorder(nil, nil, nil, container.NewCenter(btn),
				container.NewVBox(title, widget.NewLabel(readyDetail))),
		}
	case update.StateManualOnly:
		u, ok := githubURL(s.ReleaseURL)
		if !ok {
			return nil
		}
		objs := []fyne.CanvasObject{container.NewHBox(
			widget.NewLabel(fmt.Sprintf(manualFmt, s.Version)),
			widget.NewHyperlink(downloadText, u),
		)}
		if s.MoveToApplications {
			objs = append(objs, widget.NewLabel(moveToAppsHint))
		}
		return objs
	default:
		return nil
	}
}

// updatedObjects renders the one-time "Updated to" notice. The "What's new"
// link is shown only for a valid github.com release URL; onClose dismisses
// the notice.
func updatedObjects(version, releaseURL string, onClose func()) []fyne.CanvasObject {
	row := container.NewHBox(widget.NewLabelWithStyle(fmt.Sprintf(updatedFmt, version), fyne.TextAlignLeading, fyne.TextStyle{Bold: true}))
	if u, ok := githubURL(releaseURL); ok {
		row.Add(widget.NewHyperlink(whatsNewText, u))
	}
	closeBtn := widget.NewButtonWithIcon("", theme.CancelIcon(), onClose)
	closeBtn.Importance = widget.LowImportance
	return []fyne.CanvasObject{container.NewBorder(nil, nil, nil, closeBtn, row)}
}

// updateBannerView owns two independent slots in the top banner: the update
// status (re-rendered on every Status change) and the "Updated to" notice.
// Its methods mutate the UI and must run on the main goroutine (fyne.Do).
type updateBannerView struct {
	status  *fyne.Container
	updated *fyne.Container
	restart func()
}

// newUpdateBannerView adds both (initially hidden) slots to parent.
func newUpdateBannerView(parent *fyne.Container, restart func()) *updateBannerView {
	v := &updateBannerView{
		status:  container.NewVBox(),
		updated: container.NewVBox(),
		restart: restart,
	}
	v.status.Hide()
	v.updated.Hide()
	parent.Add(v.updated)
	parent.Add(v.status)
	return v
}

// showStatus replaces the status slot's contents with the rendering of s.
func (v *updateBannerView) showStatus(s update.Status) {
	setSlot(v.status, statusObjects(s, v.restart))
}

// showUpdated shows the "Updated to" notice, replacing any earlier one.
func (v *updateBannerView) showUpdated(version, releaseURL string) {
	setSlot(v.updated, updatedObjects(version, releaseURL, func() { setSlot(v.updated, nil) }))
}

// setSlot replaces slot's contents with objs. An empty slot is hidden so the
// banner VBox adds no padding for it.
func setSlot(slot *fyne.Container, objs []fyne.CanvasObject) {
	slot.Objects = objs
	if len(objs) == 0 {
		slot.Hide()
	} else {
		slot.Show()
	}
	slot.Refresh()
}

// markRelaunchAndQuit returns the quit action for "Restart now": it records
// that the app should relaunch after applying the update, then quits.
func markRelaunchAndQuit(relaunch *bool, quit func()) func() {
	return func() {
		*relaunch = true
		quit()
	}
}

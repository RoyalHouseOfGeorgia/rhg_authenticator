package gui

import (
	"fmt"
	"sync/atomic"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
	"github.com/royalhouseofgeorgia/rhg-authenticator/safego"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
)

// NewAuditTab creates the registry audit tab UI showing GitHub commit history.
func NewAuditTab(window fyne.Window) *fyne.Container {
	var commits []ghapi.RegistryCommit
	statusLabel := widget.NewLabel("")

	list := widget.NewList(
		func() int {
			return len(commits)
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("template")
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			label, ok := obj.(*widget.Label)
			if !ok {
				return
			}
			if id < 0 || id >= len(commits) {
				return
			}
			label.SetText(service.FormatCommitSummary(commits[id]))
		},
	)

	list.OnSelected = func(id widget.ListItemID) {
		if id < 0 || id >= len(commits) {
			return
		}
		if parsed := ghapi.ParseGitHubURL(commits[id].HTMLURL); parsed != nil {
			fyne.CurrentApp().OpenURL(parsed)
		}
		list.UnselectAll()
	}

	var fetching atomic.Bool
	var lastETag string
	var refreshBtn *widget.Button

	doFetch := func() {
		if !fetching.CompareAndSwap(false, true) {
			return
		}
		refreshBtn.Disable()
		statusLabel.SetText("Fetching...")
		currentETag := lastETag // capture under UI thread
		safego.Go(func() {
			result, newETag, err := ghapi.FetchRegistryCommits("", service.CommitsPerPage, currentETag)
			fyne.Do(func() {
				fetching.Store(false)
				refreshBtn.Enable()
				if err != nil {
					if ghapi.IsRateLimited(err) {
						statusLabel.SetText("GitHub API rate limit reached — try again later")
					} else {
						statusLabel.SetText("Failed to fetch registry history")
					}
					return
				}
				if result != nil { // nil means 304, keep existing commits
					commits = result
					lastETag = newETag
					list.Refresh()
					statusLabel.SetText(fmt.Sprintf("Loaded %d commits", len(commits)))
				} else {
					statusLabel.SetText("No changes since last check")
				}
			})
		})
	}

	refreshBtn = widget.NewButton("Refresh", doFetch)
	doFetch() // auto-fetch on creation

	topBar := container.NewBorder(nil, nil, nil, refreshBtn, statusLabel)
	return container.NewBorder(topBar, nil, nil, nil, list)
}

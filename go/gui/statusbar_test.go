package gui

import (
	"slices"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
)

// barLabels returns the texts of the status bar's labels, in layout order.
func barLabels(bar *fyne.Container) []string {
	var texts []string
	for _, obj := range bar.Objects {
		if l, ok := obj.(*widget.Label); ok {
			texts = append(texts, l.Text)
		}
	}
	return texts
}

func TestNewStatusBar_OnlineShowsStatsAndVersion(t *testing.T) {
	test.NewTempApp(t)
	labels := barLabels(NewStatusBar(service.Info{Version: "v1.5.1", Online: true, ActiveKeys: 2, RecentlyExpired: 1}))
	if !slices.Contains(labels, "Active keys: 2") || !slices.Contains(labels, "Expired (30d): 1") {
		t.Errorf("labels = %q, want key stats", labels)
	}
	if !slices.Contains(labels, "Version 1.5.1") {
		t.Errorf("labels = %q, want %q", labels, "Version 1.5.1")
	}
}

func TestNewStatusBar_OfflineShowsVersion(t *testing.T) {
	test.NewTempApp(t)
	labels := barLabels(NewStatusBar(service.Info{Version: "v1.5.1"}))
	if !slices.Contains(labels, "No internet") || !slices.Contains(labels, "Version 1.5.1") {
		t.Errorf("labels = %q, want %q and %q", labels, "No internet", "Version 1.5.1")
	}
}

package gui

import (
	"slices"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
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

func anyHasPrefix(texts []string, prefix string) bool {
	return slices.ContainsFunc(texts, func(s string) bool { return strings.HasPrefix(s, prefix) })
}

func TestNewStatusBar_OnlineShowsStatsAndVersion(t *testing.T) {
	test.NewTempApp(t)
	labels := barLabels(NewStatusBar(core.Registry{}, true, "v1.5.1"))
	if !anyHasPrefix(labels, "Active keys:") || !anyHasPrefix(labels, "Expired (30d):") {
		t.Errorf("labels = %q, want key stats", labels)
	}
	if !slices.Contains(labels, "Version 1.5.1") {
		t.Errorf("labels = %q, want %q", labels, "Version 1.5.1")
	}
}

func TestNewStatusBar_OfflineShowsVersion(t *testing.T) {
	test.NewTempApp(t)
	labels := barLabels(NewStatusBar(core.Registry{}, false, "v1.5.1"))
	if !slices.Contains(labels, "No internet") || !slices.Contains(labels, "Version 1.5.1") {
		t.Errorf("labels = %q, want %q and %q", labels, "No internet", "Version 1.5.1")
	}
}

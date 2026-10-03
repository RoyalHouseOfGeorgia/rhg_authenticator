package gui

import (
	"fmt"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/safego"
)

// registryStats holds computed statistics about a key registry.
type registryStats struct {
	ActiveKeys      int
	RecentlyExpired int // expired within the past 30 days
}

// computeRegistryStats computes active key count and recently-expired count
// from a registry using the given date (YYYY-MM-DD format) as "today".
// A key is active when today is on or before its to date (see core.IsDateInRange);
// from is informational, so a key with a future from date counts as active.
func computeRegistryStats(reg core.Registry, today string) registryStats {
	var stats registryStats

	todayTime, err := time.Parse("2006-01-02", today)
	if err != nil {
		return stats
	}
	thirtyDaysAgo := todayTime.AddDate(0, 0, -30).Format("2006-01-02")

	for _, key := range reg.Keys {
		active := core.IsDateInRange(today, key)
		if active {
			stats.ActiveKeys++
			continue
		}

		// Check if expired within the past 30 days.
		if key.To != nil && *key.To >= thirtyDaysAgo && *key.To < today {
			stats.RecentlyExpired++
		}
	}

	return stats
}

// NewStatusBar creates a status bar widget showing registry statistics.
// online indicates whether the registry was fetched from the remote server.
// lastUpdateCh receives the date string of the most recent registry commit
// from the audit tab.
func NewStatusBar(reg core.Registry, online bool, lastUpdateCh <-chan string) *fyne.Container {
	if !online {
		return container.NewHBox(
			widget.NewLabel("No internet"),
		)
	}

	today := time.Now().UTC().Format("2006-01-02")
	stats := computeRegistryStats(reg, today)

	activeLabel := widget.NewLabel(fmt.Sprintf("Active keys: %d", stats.ActiveKeys))
	recentLabel := widget.NewLabel(fmt.Sprintf("Expired (30d): %d", stats.RecentlyExpired))
	updatedLabel := widget.NewLabel("Last update: loading...")

	bar := container.NewHBox(
		activeLabel,
		layout.NewSpacer(),
		recentLabel,
		layout.NewSpacer(),
		updatedLabel,
	)

	safego.Go(func() {
		select {
		case date := <-lastUpdateCh:
			t, err := time.Parse(time.RFC3339, date)
			fyne.Do(func() {
				if err != nil {
					updatedLabel.SetText("Last update: unknown")
					return
				}
				updatedLabel.SetText("Last update: " + t.UTC().Format("2006-Jan-02"))
			})
		case <-time.After(15 * time.Second):
			fyne.Do(func() {
				updatedLabel.SetText("Last update: unknown")
			})
		}
	})

	return bar
}

package gui

import (
	"fmt"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

// RegistryStats holds computed statistics about a key registry.
type RegistryStats struct {
	ActiveKeys      int
	RecentlyExpired int // expired within the past 30 days
	LastUpdated     string
}

// ComputeRegistryStats computes statistics from a registry using the given date
// (YYYY-MM-DD format) as "today".
func ComputeRegistryStats(reg core.Registry, today string) RegistryStats {
	var stats RegistryStats

	todayTime, err := time.Parse("2006-01-02", today)
	if err != nil {
		return stats
	}
	thirtyDaysAgo := todayTime.AddDate(0, 0, -30).Format("2006-01-02")

	var latestFrom string
	for _, key := range reg.Keys {
		// Track the latest "from" date as a proxy for last registry update.
		if key.From > latestFrom {
			latestFrom = key.From
		}

		active := today >= key.From && (key.To == nil || today <= *key.To)
		if active {
			stats.ActiveKeys++
			continue
		}

		// Check if expired within the past 30 days.
		if key.To != nil && *key.To >= thirtyDaysAgo && *key.To < today {
			stats.RecentlyExpired++
		}
	}

	if latestFrom != "" {
		stats.LastUpdated = latestFrom
	}
	return stats
}

// NewStatusBar creates a status bar widget showing registry statistics.
// online indicates whether the registry was fetched from the remote server.
func NewStatusBar(reg core.Registry, online bool) *fyne.Container {
	if !online {
		return container.NewHBox(
			widget.NewLabel("No internet"),
		)
	}

	today := time.Now().UTC().Format("2006-01-02")
	stats := ComputeRegistryStats(reg, today)

	activeLabel := widget.NewLabel(fmt.Sprintf("Active keys: %d", stats.ActiveKeys))
	recentLabel := widget.NewLabel(fmt.Sprintf("Expired (30d): %d", stats.RecentlyExpired))

	updatedText := "Last update: unknown"
	if stats.LastUpdated != "" {
		updatedText = "Last update: " + core.FormatDateDisplay(stats.LastUpdated)
	}
	updatedLabel := widget.NewLabel(updatedText)

	return container.NewHBox(
		activeLabel,
		layout.NewSpacer(),
		recentLabel,
		layout.NewSpacer(),
		updatedLabel,
	)
}

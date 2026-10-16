package gui

import (
	"fmt"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
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

// NewStatusBar creates a status bar widget showing registry statistics and
// the app version. online indicates whether the registry was fetched from the
// remote server. version is the build version (e.g. "v1.5.1"), shown without
// its "v" prefix; local builds pass "dev" and show "Version dev".
func NewStatusBar(reg core.Registry, online bool, version string) *fyne.Container {
	versionLabel := widget.NewLabel("Version " + strings.TrimPrefix(version, "v"))

	if !online {
		return container.NewHBox(
			widget.NewLabel("No internet"),
			layout.NewSpacer(),
			versionLabel,
		)
	}

	today := time.Now().UTC().Format("2006-01-02")
	stats := computeRegistryStats(reg, today)

	activeLabel := widget.NewLabel(fmt.Sprintf("Active keys: %d", stats.ActiveKeys))
	recentLabel := widget.NewLabel(fmt.Sprintf("Expired (30d): %d", stats.RecentlyExpired))

	return container.NewHBox(
		activeLabel,
		layout.NewSpacer(),
		recentLabel,
		layout.NewSpacer(),
		versionLabel,
	)
}

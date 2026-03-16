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
}

// ComputeRegistryStats computes active key count and recently-expired count
// from a registry using the given date (YYYY-MM-DD format) as "today".
func ComputeRegistryStats(reg core.Registry, today string) RegistryStats {
	var stats RegistryStats

	todayTime, err := time.Parse("2006-01-02", today)
	if err != nil {
		return stats
	}
	thirtyDaysAgo := todayTime.AddDate(0, 0, -30).Format("2006-01-02")

	for _, key := range reg.Keys {
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
	updatedLabel := widget.NewLabel("Last update: loading...")

	bar := container.NewHBox(
		activeLabel,
		layout.NewSpacer(),
		recentLabel,
		layout.NewSpacer(),
		updatedLabel,
	)

	// TODO(tech-debt): This makes a separate GitHub API call from the audit tab's
	// fetchCommits. Could share the first commit via callback/channel to avoid the
	// duplicate request.
	go func() {
		apiURL := fmt.Sprintf(
			"https://api.github.com/repos/%s/%s/commits?path=%s&per_page=1",
			githubOwner, githubRepo, registryFilePath,
		)
		commits, _, err := fetchCommits(apiURL, "")
		fyne.Do(func() {
			if err != nil || len(commits) == 0 {
				updatedLabel.SetText("Last update: unknown")
				return
			}
			// TODO(tech-debt): Uses Author.Date (patch creation), not Committer.Date
			// (push/merge). For rebased commits these may differ. Consistent with
			// audit tab's formatCommitSummary which also uses Author.Date.
			t, err := time.Parse(time.RFC3339, commits[0].Commit.Author.Date)
			if err != nil {
				updatedLabel.SetText("Last update: unknown")
				return
			}
			updatedLabel.SetText("Last update: " + t.UTC().Format("2006-Jan-02"))
		})
	}()

	return bar
}

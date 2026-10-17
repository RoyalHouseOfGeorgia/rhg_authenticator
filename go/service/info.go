package service

import (
	"time"

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

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

func ptrStr(s string) *string { return &s }

func TestComputeRegistryStats_ActiveKeys(t *testing.T) {
	reg := core.Registry{
		Keys: []core.KeyEntry{
			{Authority: "A", From: "2025-01-01", To: nil},
			{Authority: "B", From: "2025-06-01", To: ptrStr("2026-12-31")},
		},
	}
	stats := computeRegistryStats(reg, "2026-03-15")
	if stats.ActiveKeys != 2 {
		t.Errorf("ActiveKeys = %d, want 2", stats.ActiveKeys)
	}
}

func TestComputeRegistryStats_ExpiredKey(t *testing.T) {
	reg := core.Registry{
		Keys: []core.KeyEntry{
			{Authority: "A", From: "2025-01-01", To: ptrStr("2026-03-01")},
		},
	}
	stats := computeRegistryStats(reg, "2026-03-15")
	if stats.ActiveKeys != 0 {
		t.Errorf("ActiveKeys = %d, want 0", stats.ActiveKeys)
	}
	if stats.RecentlyExpired != 1 {
		t.Errorf("RecentlyExpired = %d, want 1", stats.RecentlyExpired)
	}
}

func TestComputeRegistryStats_ExpiredOlderThan30Days(t *testing.T) {
	reg := core.Registry{
		Keys: []core.KeyEntry{
			{Authority: "A", From: "2025-01-01", To: ptrStr("2025-12-31")},
		},
	}
	stats := computeRegistryStats(reg, "2026-03-15")
	if stats.RecentlyExpired != 0 {
		t.Errorf("RecentlyExpired = %d, want 0 (expired >30 days ago)", stats.RecentlyExpired)
	}
}

func TestComputeRegistryStats_EmptyRegistry(t *testing.T) {
	reg := core.Registry{Keys: []core.KeyEntry{}}
	stats := computeRegistryStats(reg, "2026-03-15")
	if stats.ActiveKeys != 0 {
		t.Errorf("ActiveKeys = %d, want 0", stats.ActiveKeys)
	}
	if stats.RecentlyExpired != 0 {
		t.Errorf("RecentlyExpired = %d, want 0", stats.RecentlyExpired)
	}
}

func TestComputeRegistryStats_FutureFromIsActive(t *testing.T) {
	reg := core.Registry{
		Keys: []core.KeyEntry{
			{Authority: "A", From: "2027-01-01", To: nil},
		},
	}
	stats := computeRegistryStats(reg, "2026-03-15")
	if stats.ActiveKeys != 1 {
		t.Errorf("ActiveKeys = %d, want 1 (from is informational)", stats.ActiveKeys)
	}
}

func TestComputeRegistryStats_ToEqualsTodayIsActive(t *testing.T) {
	reg := core.Registry{
		Keys: []core.KeyEntry{
			{Authority: "A", From: "2025-01-01", To: ptrStr("2026-03-15")},
		},
	}
	stats := computeRegistryStats(reg, "2026-03-15")
	if stats.ActiveKeys != 1 {
		t.Errorf("ActiveKeys = %d, want 1 (to is inclusive)", stats.ActiveKeys)
	}
	if stats.RecentlyExpired != 0 {
		t.Errorf("RecentlyExpired = %d, want 0", stats.RecentlyExpired)
	}
}

func TestComputeRegistryStats_ExpiredExactly30DaysAgo(t *testing.T) {
	reg := core.Registry{
		Keys: []core.KeyEntry{
			{Authority: "A", From: "2025-01-01", To: ptrStr("2026-02-13")},
		},
	}
	stats := computeRegistryStats(reg, "2026-03-15")
	if stats.ActiveKeys != 0 {
		t.Errorf("ActiveKeys = %d, want 0", stats.ActiveKeys)
	}
	if stats.RecentlyExpired != 1 {
		t.Errorf("RecentlyExpired = %d, want 1 (30-day boundary is inclusive)", stats.RecentlyExpired)
	}
}

func TestComputeRegistryStats_InvalidDate(t *testing.T) {
	reg := core.Registry{
		Keys: []core.KeyEntry{
			{Authority: "A", From: "2025-01-01", To: nil},
		},
	}
	stats := computeRegistryStats(reg, "not-a-date")
	if stats.ActiveKeys != 0 {
		t.Errorf("ActiveKeys = %d, want 0 (invalid today date)", stats.ActiveKeys)
	}
}

func TestComputeRegistryStats_MixedKeys(t *testing.T) {
	reg := core.Registry{
		Keys: []core.KeyEntry{
			{Authority: "Active", From: "2025-01-01", To: nil},
			{Authority: "RecentExpired", From: "2025-01-01", To: ptrStr("2026-03-10")},
			{Authority: "OldExpired", From: "2024-01-01", To: ptrStr("2024-12-31")},
			{Authority: "FutureFrom", From: "2027-01-01", To: nil},
		},
	}
	stats := computeRegistryStats(reg, "2026-03-15")
	if stats.ActiveKeys != 2 {
		t.Errorf("ActiveKeys = %d, want 2 (future from counts as active)", stats.ActiveKeys)
	}
	if stats.RecentlyExpired != 1 {
		t.Errorf("RecentlyExpired = %d, want 1", stats.RecentlyExpired)
	}
}

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

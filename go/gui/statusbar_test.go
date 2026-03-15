package gui

import (
	"testing"

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
	stats := ComputeRegistryStats(reg, "2026-03-15")
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
	stats := ComputeRegistryStats(reg, "2026-03-15")
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
	stats := ComputeRegistryStats(reg, "2026-03-15")
	if stats.RecentlyExpired != 0 {
		t.Errorf("RecentlyExpired = %d, want 0 (expired >30 days ago)", stats.RecentlyExpired)
	}
}

func TestComputeRegistryStats_LastUpdated(t *testing.T) {
	reg := core.Registry{
		Keys: []core.KeyEntry{
			{Authority: "A", From: "2025-01-01", To: nil},
			{Authority: "B", From: "2026-02-15", To: nil},
			{Authority: "C", From: "2025-06-01", To: nil},
		},
	}
	stats := ComputeRegistryStats(reg, "2026-03-15")
	if stats.LastUpdated != "2026-02-15" {
		t.Errorf("LastUpdated = %q, want %q", stats.LastUpdated, "2026-02-15")
	}
}

func TestComputeRegistryStats_EmptyRegistry(t *testing.T) {
	reg := core.Registry{Keys: []core.KeyEntry{}}
	stats := ComputeRegistryStats(reg, "2026-03-15")
	if stats.ActiveKeys != 0 {
		t.Errorf("ActiveKeys = %d, want 0", stats.ActiveKeys)
	}
	if stats.RecentlyExpired != 0 {
		t.Errorf("RecentlyExpired = %d, want 0", stats.RecentlyExpired)
	}
	if stats.LastUpdated != "" {
		t.Errorf("LastUpdated = %q, want empty", stats.LastUpdated)
	}
}

func TestComputeRegistryStats_NotYetActive(t *testing.T) {
	reg := core.Registry{
		Keys: []core.KeyEntry{
			{Authority: "A", From: "2027-01-01", To: nil},
		},
	}
	stats := ComputeRegistryStats(reg, "2026-03-15")
	if stats.ActiveKeys != 0 {
		t.Errorf("ActiveKeys = %d, want 0 (key not yet active)", stats.ActiveKeys)
	}
}

func TestComputeRegistryStats_InvalidDate(t *testing.T) {
	reg := core.Registry{
		Keys: []core.KeyEntry{
			{Authority: "A", From: "2025-01-01", To: nil},
		},
	}
	stats := ComputeRegistryStats(reg, "not-a-date")
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
			{Authority: "NotYetActive", From: "2027-01-01", To: nil},
		},
	}
	stats := ComputeRegistryStats(reg, "2026-03-15")
	if stats.ActiveKeys != 1 {
		t.Errorf("ActiveKeys = %d, want 1", stats.ActiveKeys)
	}
	if stats.RecentlyExpired != 1 {
		t.Errorf("RecentlyExpired = %d, want 1", stats.RecentlyExpired)
	}
	if stats.LastUpdated != "2027-01-01" {
		t.Errorf("LastUpdated = %q, want %q", stats.LastUpdated, "2027-01-01")
	}
}

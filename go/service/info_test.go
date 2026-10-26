package service

import (
	"reflect"
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

func ptrStr(s string) *string { return &s }

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

func TestStatusItems(t *testing.T) {
	stats := registryStats{ActiveKeys: 3, RecentlyExpired: 2}
	for _, tc := range []struct {
		name    string
		version string
		online  bool
		want    []string
	}{
		{"online", "v1.5.1", true, []string{"Active keys: 3", "Expired (30d): 2", "Version 1.5.1"}},
		{"offline", "v1.5.1", false, []string{"No internet", "Version 1.5.1"}},
		{"dev build", "dev", true, []string{"Active keys: 3", "Expired (30d): 2", "Version dev"}},
		{"only the leading v", "vv2", false, []string{"No internet", "Version v2"}},
	} {
		if got := statusItems(tc.version, tc.online, stats); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: statusItems = %q, want %q", tc.name, got, tc.want)
		}
	}
}

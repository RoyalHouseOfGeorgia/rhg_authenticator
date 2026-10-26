package service

import (
	"reflect"
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

func ptrStr(s string) *string { return &s }

func TestComputeRegistryStats(t *testing.T) {
	cases := []struct {
		name       string
		keys       []core.KeyEntry
		today      string
		wantActive int
		wantRecent int
	}{
		{
			name:       "to equals today is active (to is inclusive)",
			keys:       []core.KeyEntry{{Authority: "A", From: "2025-01-01", To: ptrStr("2026-03-15")}},
			today:      "2026-03-15",
			wantActive: 1,
		},
		{
			name:       "expired exactly 30 days ago is recent (boundary is inclusive)",
			keys:       []core.KeyEntry{{Authority: "A", From: "2025-01-01", To: ptrStr("2026-02-13")}},
			today:      "2026-03-15",
			wantRecent: 1,
		},
		{
			name:  "invalid today date counts nothing",
			keys:  []core.KeyEntry{{Authority: "A", From: "2025-01-01", To: nil}},
			today: "not-a-date",
		},
		{
			name: "mixed keys (future from counts as active)",
			keys: []core.KeyEntry{
				{Authority: "Active", From: "2025-01-01", To: nil},
				{Authority: "RecentExpired", From: "2025-01-01", To: ptrStr("2026-03-10")},
				{Authority: "OldExpired", From: "2024-01-01", To: ptrStr("2024-12-31")},
				{Authority: "FutureFrom", From: "2027-01-01", To: nil},
			},
			today:      "2026-03-15",
			wantActive: 2,
			wantRecent: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stats := computeRegistryStats(core.Registry{Keys: tc.keys}, tc.today)
			if stats.ActiveKeys != tc.wantActive {
				t.Errorf("ActiveKeys = %d, want %d", stats.ActiveKeys, tc.wantActive)
			}
			if stats.RecentlyExpired != tc.wantRecent {
				t.Errorf("RecentlyExpired = %d, want %d", stats.RecentlyExpired, tc.wantRecent)
			}
		})
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

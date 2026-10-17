package gui

import (
	"errors"
	"testing"

	"fyne.io/fyne/v2/test"

	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
)

// The fetch itself (AuditCommits against GitHub) is covered in service; these
// tests never call Refresh, so they stay offline.

func newTestAuditTab(t *testing.T) *AuditTab {
	t.Helper()
	test.NewTempApp(t)
	return NewAuditTab(newTestAppWithConfig(t, func(*service.Config) {}))
}

func TestNewAuditTab_NoFetch(t *testing.T) {
	at := newTestAuditTab(t)
	if at.statusLabel.Text != "" || at.refreshBtn.Disabled() || at.list.Length() != 0 {
		t.Errorf("status %q, Refresh disabled %v, %d rows", at.statusLabel.Text, at.refreshBtn.Disabled(), at.list.Length())
	}
}

func TestAuditTab_AuditDone(t *testing.T) {
	rows := []service.AuditRow{
		{Summary: "2026-Jan-02  Alice — add key", URL: "https://github.com/o/r/commit/1"},
		{Summary: "2026-Jan-01  Bob — init"},
	}

	t.Run("result", func(t *testing.T) {
		at := newTestAuditTab(t)
		at.refreshBtn.Disable()
		at.auditDone(service.AuditResult{Rows: rows, Status: "Loaded 2 commits"}, nil)
		if at.statusLabel.Text != "Loaded 2 commits" || at.refreshBtn.Disabled() || at.list.Length() != 2 {
			t.Errorf("status %q, Refresh disabled %v, %d rows", at.statusLabel.Text, at.refreshBtn.Disabled(), at.list.Length())
		}
	})
	t.Run("error keeps rows", func(t *testing.T) {
		at := newTestAuditTab(t)
		at.auditDone(service.AuditResult{Rows: rows, Status: "Loaded 2 commits"}, nil)
		at.refreshBtn.Disable()
		at.auditDone(service.AuditResult{}, errors.New("Failed to fetch registry history"))
		if at.statusLabel.Text != "Failed to fetch registry history" || at.refreshBtn.Disabled() || at.list.Length() != 2 {
			t.Errorf("status %q, Refresh disabled %v, %d rows", at.statusLabel.Text, at.refreshBtn.Disabled(), at.list.Length())
		}
	})
	t.Run("busy changes nothing", func(t *testing.T) {
		at := newTestAuditTab(t)
		at.refreshBtn.Disable()
		at.statusLabel.SetText("Fetching...")
		at.auditDone(service.AuditResult{}, service.ErrBusy)
		if at.statusLabel.Text != "Fetching..." || !at.refreshBtn.Disabled() {
			t.Errorf("status %q, Refresh disabled %v", at.statusLabel.Text, at.refreshBtn.Disabled())
		}
	})
}

// Selecting a row (with or without a commit URL) opens it and clears the
// selection; an out-of-range id is ignored.
func TestAuditTab_RowSelected(t *testing.T) {
	at := newTestAuditTab(t)
	at.auditDone(service.AuditResult{Rows: []service.AuditRow{
		{Summary: "with URL", URL: "https://github.com/o/r/commit/1"},
		{Summary: "without URL"},
	}}, nil)
	selections := 0
	at.list.OnSelected = func(id int) { selections++; at.rowSelected(id) }
	for _, id := range []int{0, 1} {
		at.list.Select(id)
		at.list.Select(id) // fires again only if the first selection was cleared
	}
	if selections != 4 {
		t.Errorf("OnSelected fired %d times, want 4 (selection not cleared)", selections)
	}
	at.rowSelected(5)
}

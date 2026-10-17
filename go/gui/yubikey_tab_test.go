package gui

import (
	"slices"
	"testing"

	"fyne.io/fyne/v2/test"
)

// TestNewYubiKeyTab_OfflineDisablesCheck: without the registry the check
// button is disabled and the label says why.
func TestNewYubiKeyTab_OfflineDisablesCheck(t *testing.T) {
	test.NewTempApp(t)
	w := test.NewWindow(nil)
	defer w.Close()

	tab := NewYubiKeyTab(newTestApp(t, NewEvents(), &cancelPrompter{}))
	btn := findButton(t, tab, "Check YubiKey")
	if btn == nil || !btn.Disabled() {
		t.Fatalf("check button = %v, want present and disabled", btn)
	}
	if !slices.Contains(labelTexts(t, tab), "Registry unavailable — connect to internet to check key") {
		t.Errorf("labels = %q", labelTexts(t, tab))
	}
}

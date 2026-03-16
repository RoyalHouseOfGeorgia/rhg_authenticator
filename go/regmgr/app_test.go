package regmgr

import (
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

func TestCanSave_EmptyRegistry(t *testing.T) {
	reg := core.Registry{Keys: nil}
	if canSave(reg) {
		t.Error("canSave should return false for empty registry")
	}
}

func TestCanSave_EmptySlice(t *testing.T) {
	reg := core.Registry{Keys: []core.KeyEntry{}}
	if canSave(reg) {
		t.Error("canSave should return false for zero-length Keys slice")
	}
}

func TestCanSave_NonEmpty(t *testing.T) {
	reg := core.Registry{Keys: []core.KeyEntry{{Authority: "A"}}}
	if !canSave(reg) {
		t.Error("canSave should return true for non-empty registry")
	}
}

func TestAppState_InitialValues(t *testing.T) {
	state := &appState{selected: -1}
	if state.filePath != "" {
		t.Error("expected empty filePath initially")
	}
	if state.dirty {
		t.Error("expected dirty = false initially")
	}
	if state.selected != -1 {
		t.Errorf("expected selected = -1 initially, got %d", state.selected)
	}
	if len(state.registry.Keys) != 0 {
		t.Errorf("expected empty registry initially, got %d keys", len(state.registry.Keys))
	}
}

func TestTableColumns(t *testing.T) {
	if len(tableColumns) != len(tableColumnWidths) {
		t.Errorf("tableColumns (%d) and tableColumnWidths (%d) length mismatch",
			len(tableColumns), len(tableColumnWidths))
	}
	expected := []string{"#", "Authority", "From", "To", "Note", "Fingerprint"}
	for i, col := range expected {
		if tableColumns[i] != col {
			t.Errorf("tableColumns[%d] = %q, want %q", i, tableColumns[i], col)
		}
	}
}

func TestIsDirty_InitiallyFalse(t *testing.T) {
	state := &appState{selected: -1}
	rt := &RegistryTab{state: state}
	if rt.IsDirty() {
		t.Error("expected IsDirty() = false initially")
	}
}

func TestIsDirty_AfterMutation(t *testing.T) {
	state := &appState{selected: -1, dirty: true}
	rt := &RegistryTab{state: state}
	if !rt.IsDirty() {
		t.Error("expected IsDirty() = true after mutation")
	}
}

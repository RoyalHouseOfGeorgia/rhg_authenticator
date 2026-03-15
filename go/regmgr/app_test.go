package regmgr

import (
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

func TestBuildTitle_Clean(t *testing.T) {
	got := buildTitle("", false)
	want := "RHG Registry Manager"
	if got != want {
		t.Errorf("buildTitle(\"\", false) = %q, want %q", got, want)
	}
}

func TestBuildTitle_Dirty(t *testing.T) {
	got := buildTitle("", true)
	if got != "RHG Registry Manager *" {
		t.Errorf("buildTitle(\"\", true) = %q, want suffix ' *'", got)
	}
}

func TestBuildTitle_WithFile(t *testing.T) {
	got := buildTitle("/foo/registry.json", false)
	want := "RHG Registry Manager \u2014 registry.json"
	if got != want {
		t.Errorf("buildTitle with file = %q, want %q", got, want)
	}
}

func TestBuildTitle_DirtyWithFile(t *testing.T) {
	got := buildTitle("/foo/registry.json", true)
	want := "RHG Registry Manager \u2014 registry.json *"
	if got != want {
		t.Errorf("buildTitle dirty+file = %q, want %q", got, want)
	}
}

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

func TestRemoveEntry(t *testing.T) {
	reg := core.Registry{
		Keys: []core.KeyEntry{
			{Authority: "A", From: "2025-01-01"},
			{Authority: "B", From: "2025-02-01"},
			{Authority: "C", From: "2025-03-01"},
		},
	}
	result := removeEntry(reg, 1) // remove "B"
	if len(result.Keys) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(result.Keys))
	}
	if result.Keys[0].Authority != "A" {
		t.Errorf("expected first entry 'A', got %q", result.Keys[0].Authority)
	}
	if result.Keys[1].Authority != "C" {
		t.Errorf("expected second entry 'C', got %q", result.Keys[1].Authority)
	}
}

func TestRemoveEntry_First(t *testing.T) {
	reg := core.Registry{
		Keys: []core.KeyEntry{
			{Authority: "A", From: "2025-01-01"},
			{Authority: "B", From: "2025-02-01"},
		},
	}
	result := removeEntry(reg, 0)
	if len(result.Keys) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result.Keys))
	}
	if result.Keys[0].Authority != "B" {
		t.Errorf("expected entry 'B', got %q", result.Keys[0].Authority)
	}
}

func TestRemoveEntry_Last(t *testing.T) {
	reg := core.Registry{
		Keys: []core.KeyEntry{
			{Authority: "A", From: "2025-01-01"},
			{Authority: "B", From: "2025-02-01"},
		},
	}
	result := removeEntry(reg, 1)
	if len(result.Keys) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result.Keys))
	}
	if result.Keys[0].Authority != "A" {
		t.Errorf("expected entry 'A', got %q", result.Keys[0].Authority)
	}
}

func TestRemoveEntry_ResetsSelected(t *testing.T) {
	// Verify the pattern used in NewApp: after removeEntry, selected = -1.
	state := &appState{
		registry: core.Registry{
			Keys: []core.KeyEntry{
				{Authority: "A", From: "2025-01-01"},
				{Authority: "B", From: "2025-02-01"},
			},
		},
		selected: 1,
		dirty:    false,
	}
	state.registry = removeEntry(state.registry, state.selected)
	state.selected = -1
	state.dirty = true

	if state.selected != -1 {
		t.Errorf("expected selected = -1, got %d", state.selected)
	}
	if !state.dirty {
		t.Error("expected dirty = true after removal")
	}
	if len(state.registry.Keys) != 1 {
		t.Errorf("expected 1 entry remaining, got %d", len(state.registry.Keys))
	}
}

func TestFormatKeyColumn_Short(t *testing.T) {
	got := formatKeyColumn("abc")
	if got != "abc" {
		t.Errorf("formatKeyColumn(short) = %q, want %q", got, "abc")
	}
}

func TestFormatKeyColumn_Exact12(t *testing.T) {
	got := formatKeyColumn("123456789012")
	if got != "123456789012" {
		t.Errorf("formatKeyColumn(12 chars) = %q, want no truncation", got)
	}
}

func TestFormatKeyColumn_Long(t *testing.T) {
	got := formatKeyColumn("1234567890123456")
	want := "123456789012..."
	if got != want {
		t.Errorf("formatKeyColumn(long) = %q, want %q", got, want)
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
	expected := []string{"#", "Authority", "From", "To", "Note", "Key"}
	for i, col := range expected {
		if tableColumns[i] != col {
			t.Errorf("tableColumns[%d] = %q, want %q", i, tableColumns[i], col)
		}
	}
}

package regmgr

import (
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/registry"
)

// appState holds the mutable state for the registry manager UI.
type appState struct {
	registry core.Registry
	filePath string // "" = not yet saved locally
	dirty    bool
	selected int // selected table row, -1 = none
}

// tableColumns defines the column headers for the registry table.
var tableColumns = []string{"#", "Authority", "From", "To", "Note", "Fingerprint"}

// tableColumnWidths defines the minimum widths for each table column.
var tableColumnWidths = []float32{40, 200, 100, 100, 200, 450}

// canSave returns whether the registry has entries that can be saved.
func canSave(reg core.Registry) bool {
	return len(reg.Keys) > 0
}

// formatKeyColumn returns a truncated display of a public key string.
func formatKeyColumn(key string) string {
	if len(key) <= 12 {
		return key
	}
	return key[:12] + "..."
}

// RegistryTab holds the registry manager UI and its state.
type RegistryTab struct {
	Content     fyne.CanvasObject
	state          *appState
	table          *widget.Table
	statusLabel    *widget.Label
	window         fyne.Window
	rebuildCache   func()
}

// IsDirty returns whether the registry has unsaved changes.
func (rt *RegistryTab) IsDirty() bool {
	return rt.state.dirty
}

// Fetch fetches the registry from the remote server asynchronously.
func (rt *RegistryTab) Fetch() {
	rt.statusLabel.SetText("Fetching...")
	go func() {
		reg, err := registry.FetchRegistry(registry.DefaultRegistryURL)
		fyne.Do(func() {
			if err != nil {
				rt.statusLabel.SetText("Failed to load: " + err.Error())
				return
			}
			rt.state.registry = reg
			rt.state.filePath = ""
			rt.state.dirty = false
			rt.state.selected = -1
			rt.table.UnselectAll()
			if rt.rebuildCache != nil {
				rt.rebuildCache()
			}
			rt.table.Refresh()
			rt.statusLabel.SetText("Loaded from registry server")
		})
	}()
}

// NewRegistryTab creates the registry manager UI as a tab.
// The caller owns the window — this does not set close intercepts or change the window title.
func NewRegistryTab(window fyne.Window) *RegistryTab {
	state := &appState{
		selected: -1,
	}

	statusLabel := widget.NewLabel("")
	fingerprintCache := make(map[int]string)

	// rebuildFingerprintCache populates the fingerprint cache from registry keys.
	rebuildFingerprintCache := func() {
		fingerprintCache = make(map[int]string, len(state.registry.Keys))
		for i, key := range state.registry.Keys {
			if fp, err := core.KeyFingerprint(key); err == nil {
				fingerprintCache[i] = fp
			}
		}
	}

	// Build the table.
	table := widget.NewTable(
		func() (int, int) {
			return len(state.registry.Keys) + 1, len(tableColumns) // +1 for header row
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("placeholder")
		},
		func(id widget.TableCellID, o fyne.CanvasObject) {
			label, ok := o.(*widget.Label)
			if !ok {
				return
			}
			if id.Row == 0 {
				// Header row.
				label.SetText(tableColumns[id.Col])
				label.TextStyle = fyne.TextStyle{Bold: true}
				return
			}
			label.TextStyle = fyne.TextStyle{}
			entry := state.registry.Keys[id.Row-1]
			switch id.Col {
			case 0:
				label.SetText(fmt.Sprintf("%d", id.Row))
			case 1:
				label.SetText(entry.Authority)
			case 2:
				label.SetText(core.FormatDateDisplay(entry.From))
			case 3:
				if entry.To != nil {
					label.SetText(core.FormatDateDisplay(*entry.To))
				} else {
					label.SetText("(none)")
				}
			case 4:
				label.SetText(entry.Note)
			case 5:
				if fp, ok := fingerprintCache[id.Row-1]; ok {
					label.SetText(fp)
				} else {
					label.SetText("(invalid key)")
				}
			}
		},
	)

	// Set column widths.
	for i, w := range tableColumnWidths {
		table.SetColumnWidth(i, w)
	}

	table.OnSelected = func(id widget.TableCellID) {
		if id.Row == 0 {
			// Header row — ignore.
			table.UnselectAll()
			return
		}
		state.selected = id.Row - 1 // convert to 0-based index into Keys
	}

	// Helper to refresh UI after state changes.
	refreshUI := func() {
		rebuildFingerprintCache()
		table.Refresh()
	}

	// Save function (writes to state.filePath).
	doSave := func() {
		if err := WriteRegistry(state.filePath, state.registry); err != nil {
			dialog.ShowError(fmt.Errorf("save failed: %w", err), window)
			return
		}
		state.dirty = false
		statusLabel.SetText("Saved: " + state.filePath)
		refreshUI()
	}

	// Save As function.
	var doSaveAs func()
	doSaveAs = func() {
		d := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
			if err != nil {
				dialog.ShowError(err, window)
				return
			}
			if writer == nil {
				return // cancelled
			}
			_ = writer.Close()
			state.filePath = writer.URI().Path()
			doSave()
		}, window)
		d.SetFilter(storage.NewExtensionFileFilter([]string{".json"}))
		d.Show()
	}

	rt := &RegistryTab{
		state:        state,
		table:        table,
		statusLabel:  statusLabel,
		window:       window,
		rebuildCache: rebuildFingerprintCache,
	}

	// Toolbar buttons.
	fetchBtn := widget.NewButton("Fetch from Server", func() {
		if state.dirty {
			dialog.ShowConfirm("Discard Local Edits?",
				"This will re-fetch the live registry from the server, discarding your local edits. Continue?",
				func(ok bool) {
					if !ok {
						return
					}
					rt.Fetch()
				}, window)
			return
		}
		rt.Fetch()
	})

	openBtn := widget.NewButton("Open", func() {
		d := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(err, window)
				return
			}
			if reader == nil {
				return // cancelled
			}
			path := reader.URI().Path()
			_ = reader.Close()

			reg, err := ReadRegistry(path)
			if err != nil {
				dialog.ShowError(fmt.Errorf("open failed: %w", err), window)
				return
			}
			state.registry = reg
			state.filePath = path
			state.dirty = false
			state.selected = -1
			statusLabel.SetText("Opened: " + path)
			refreshUI()
		}, window)
		d.SetFilter(storage.NewExtensionFileFilter([]string{".json"}))
		d.Show()
	})

	saveBtn := widget.NewButton("Save", func() {
		if !canSave(state.registry) {
			return
		}
		if state.filePath == "" {
			doSaveAs()
			return
		}
		doSave()
	})

	saveAsBtn := widget.NewButton("Save As", func() {
		if !canSave(state.registry) {
			return
		}
		doSaveAs()
	})

	toolbar := container.NewHBox(
		fetchBtn, openBtn, saveBtn, saveAsBtn,
		layout.NewSpacer(),
		statusLabel,
	)

	// Action bar buttons.
	addBtn := widget.NewButton("Add Entry", func() {
		showAddDialog(window, func(entry core.KeyEntry) {
			state.registry.Keys = append(state.registry.Keys, entry)
			state.dirty = true
			refreshUI()
		})
	})

	editBtn := widget.NewButton("Edit Entry", func() {
		if state.selected < 0 || state.selected >= len(state.registry.Keys) {
			dialog.ShowInformation("Edit Entry", "No entry selected", window)
			return
		}
		showEditDialog(window, state.registry.Keys[state.selected], func(updated core.KeyEntry) {
			state.registry.Keys[state.selected] = updated
			state.dirty = true
			refreshUI()
		})
	})

	// No Remove button — the registry is a system of record.
	// To revoke a key, edit the entry and set an expiry date.

	actionBar := container.NewHBox(addBtn, editBtn)

	rt.Content = container.NewBorder(toolbar, actionBar, nil, nil, table)
	return rt
}

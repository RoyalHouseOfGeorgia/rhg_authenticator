package regmgr

import (
	"fmt"
	"path/filepath"

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
var tableColumns = []string{"#", "Authority", "From", "To", "Note", "Key"}

// tableColumnWidths defines the minimum widths for each table column.
var tableColumnWidths = []float32{40, 200, 100, 100, 200, 150}

// buildTitle returns the window title string based on file path and dirty state.
func buildTitle(filePath string, dirty bool) string {
	title := "RHG Registry Manager"
	if filePath != "" {
		title += " \u2014 " + filepath.Base(filePath)
	}
	if dirty {
		title += " *"
	}
	return title
}

// canSave returns whether the registry has entries that can be saved.
func canSave(reg core.Registry) bool {
	return len(reg.Keys) > 0
}

// removeEntry removes the entry at index from the registry keys slice.
// Returns the modified registry. Panics if index is out of range.
func removeEntry(reg core.Registry, index int) core.Registry {
	reg.Keys = append(reg.Keys[:index], reg.Keys[index+1:]...)
	return reg
}

// formatKeyColumn returns a truncated display of a public key string.
func formatKeyColumn(key string) string {
	if len(key) <= 12 {
		return key
	}
	return key[:12] + "..."
}

// NewApp creates the full registry manager UI and returns it as a CanvasObject.
// It sets up the close intercept on the provided window.
func NewApp(window fyne.Window) fyne.CanvasObject {
	state := &appState{
		selected: -1,
	}

	statusLabel := widget.NewLabel("Loading...")

	// Build the table.
	table := widget.NewTable(
		func() (int, int) {
			return len(state.registry.Keys) + 1, len(tableColumns) // +1 for header row
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("placeholder")
		},
		func(id widget.TableCellID, o fyne.CanvasObject) {
			label := o.(*widget.Label)
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
				label.SetText(entry.From)
			case 3:
				if entry.To != nil {
					label.SetText(*entry.To)
				} else {
					label.SetText("(none)")
				}
			case 4:
				label.SetText(entry.Note)
			case 5:
				label.SetText(formatKeyColumn(entry.PublicKey))
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
		table.Refresh()
		window.SetTitle(buildTitle(state.filePath, state.dirty))
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

	// Toolbar buttons.
	fetchBtn := widget.NewButton("Fetch from Server", func() {
		if state.dirty {
			dialog.ShowConfirm("Discard Local Edits?",
				"This will re-fetch the live registry from the server, discarding your local edits. Continue?",
				func(ok bool) {
					if !ok {
						return
					}
					doFetch(window, state, table, statusLabel, refreshUI)
				}, window)
			return
		}
		doFetch(window, state, table, statusLabel, refreshUI)
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

	removeBtn := widget.NewButton("Remove Entry", func() {
		if state.selected < 0 || state.selected >= len(state.registry.Keys) {
			dialog.ShowInformation("Remove Entry", "No entry selected", window)
			return
		}
		entry := state.registry.Keys[state.selected]
		msg := fmt.Sprintf("Remove %s (from %s)?", entry.Authority, entry.From)
		dialog.ShowConfirm("Remove Entry", msg, func(ok bool) {
			if !ok {
				return
			}
			state.registry = removeEntry(state.registry, state.selected)
			state.selected = -1
			state.dirty = true
			table.UnselectAll()
			refreshUI()
		}, window)
	})

	actionBar := container.NewHBox(addBtn, editBtn, removeBtn)

	// Close intercept for unsaved changes.
	window.SetCloseIntercept(func() {
		if !state.dirty {
			window.Close()
			return
		}
		dialog.ShowConfirm("Unsaved Changes", "You have unsaved changes. Discard?", func(ok bool) {
			if ok {
				window.Close()
			}
		}, window)
	})

	// Auto-fetch on startup.
	go func() {
		reg, err := FetchRegistry(registry.DefaultRegistryURL)
		fyne.Do(func() {
			if err != nil {
				statusLabel.SetText("Failed to load: " + err.Error())
				return
			}
			state.registry = reg
			state.selected = -1
			refreshUI()
			statusLabel.SetText("Loaded from registry server")
		})
	}()

	return container.NewBorder(toolbar, actionBar, nil, nil, table)
}

// doFetch performs the remote registry fetch and updates state on success.
func doFetch(window fyne.Window, state *appState, table *widget.Table, statusLabel *widget.Label, refreshUI func()) {
	statusLabel.SetText("Fetching...")
	go func() {
		reg, err := FetchRegistry(registry.DefaultRegistryURL)
		fyne.Do(func() {
			if err != nil {
				statusLabel.SetText("Fetch failed: " + err.Error())
				dialog.ShowError(fmt.Errorf("fetch failed: %w", err), window)
				return
			}
			state.registry = reg
			state.filePath = ""
			state.dirty = false
			state.selected = -1
			table.UnselectAll()
			refreshUI()
			statusLabel.SetText("Loaded from registry server")
		})
	}()
}

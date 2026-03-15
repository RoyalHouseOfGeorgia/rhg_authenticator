package regmgr

import (
	"os"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
	xwidget "fyne.io/x/fyne/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"golang.org/x/text/unicode/norm"
)

// buildEntry constructs a KeyEntry from form values.
func buildEntry(authority, from string, to *string, publicKey, note string) core.KeyEntry {
	return core.KeyEntry{
		Authority: norm.NFC.String(strings.TrimSpace(authority)),
		From:      from,
		To:        to,
		Algorithm: "Ed25519",
		PublicKey:  publicKey,
		Note:      note,
	}
}

// showAddDialog shows a dialog for adding a new key entry.
func showAddDialog(window fyne.Window, onAdd func(core.KeyEntry)) {
	authorityEntry := widget.NewEntry()
	authorityEntry.SetPlaceHolder("Authority name")

	// From date picker.
	fromEntry := widget.NewEntry()
	fromEntry.SetText(time.Now().UTC().Format("2006-01-02"))
	fromEntry.Disable()
	fromCalButton := widget.NewButton("\U0001F4C5", func() {
		cal := xwidget.NewCalendar(time.Now().UTC(), func(t time.Time) {
			fromEntry.SetText(t.Format("2006-01-02"))
		})
		dialog.ShowCustom("Select Date", "Close", cal, window)
	})
	fromRow := container.NewBorder(nil, nil, nil, fromCalButton, fromEntry)

	// To date picker with "No expiry" checkbox.
	toEntry := widget.NewEntry()
	toEntry.Disable()
	toCalButton := widget.NewButton("\U0001F4C5", func() {
		cal := xwidget.NewCalendar(time.Now().UTC(), func(t time.Time) {
			toEntry.SetText(t.Format("2006-01-02"))
		})
		dialog.ShowCustom("Select Date", "Close", cal, window)
	})
	toCalButton.Disable()
	toRow := container.NewBorder(nil, nil, nil, toCalButton, toEntry)

	noExpiryCheck := widget.NewCheck("No expiry", func(checked bool) {
		if checked {
			toEntry.SetText("")
			toEntry.Disable()
			toCalButton.Disable()
		} else {
			toEntry.Enable()
			toCalButton.Enable()
		}
	})
	noExpiryCheck.SetChecked(true)

	// Public key import.
	var importedKey string
	keyLabel := widget.NewLabel("No key imported")
	keyLabel.Wrapping = fyne.TextWrapBreak
	errorLabel := widget.NewLabel("")
	errorLabel.Wrapping = fyne.TextWrapBreak

	importBtn := widget.NewButton("Import Certificate", func() {
		d := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				errorLabel.SetText(err.Error())
				return
			}
			if reader == nil {
				return // cancelled
			}
			defer reader.Close()

			data, err := os.ReadFile(reader.URI().Path())
			if err != nil {
				errorLabel.SetText("Failed to read file: " + err.Error())
				keyLabel.SetText("No key imported")
				importedKey = ""
				return
			}

			key, err := ExtractEd25519Key(data)
			if err != nil {
				errorLabel.SetText(err.Error())
				keyLabel.SetText("No key imported")
				importedKey = ""
				return
			}

			importedKey = key
			keyLabel.SetText(key)
			errorLabel.SetText("")
		}, window)
		d.SetFilter(storage.NewExtensionFileFilter([]string{".crt", ".pem"}))
		d.Show()
	})

	noteEntry := widget.NewMultiLineEntry()
	noteEntry.SetPlaceHolder("Optional note")

	formContent := container.NewVBox(
		widget.NewLabel("Authority"),
		authorityEntry,
		widget.NewLabel("From date"),
		fromRow,
		widget.NewLabel("To date"),
		toRow,
		noExpiryCheck,
		widget.NewLabel("Public Key"),
		importBtn,
		keyLabel,
		errorLabel,
		widget.NewLabel("Note"),
		noteEntry,
	)

	dialog.ShowCustomConfirm("Add Entry", "Add", "Cancel", formContent, func(ok bool) {
		if !ok {
			return
		}
		authority := strings.TrimSpace(authorityEntry.Text)
		if authority == "" {
			return
		}
		if importedKey == "" {
			return
		}
		if fromEntry.Text == "" {
			return
		}

		var to *string
		if !noExpiryCheck.Checked && toEntry.Text != "" {
			t := toEntry.Text
			to = &t
		}

		entry := buildEntry(authorityEntry.Text, fromEntry.Text, to, importedKey, noteEntry.Text)
		onAdd(entry)
	}, window)
}

// showEditDialog shows a dialog for editing an existing key entry.
func showEditDialog(window fyne.Window, entry core.KeyEntry, onSave func(core.KeyEntry)) {
	authorityEntry := widget.NewEntry()
	authorityEntry.SetText(entry.Authority)

	// From date picker.
	fromEntry := widget.NewEntry()
	fromEntry.SetText(entry.From)
	fromEntry.Disable()
	fromCalButton := widget.NewButton("\U0001F4C5", func() {
		cal := xwidget.NewCalendar(time.Now().UTC(), func(t time.Time) {
			fromEntry.SetText(t.Format("2006-01-02"))
		})
		dialog.ShowCustom("Select Date", "Close", cal, window)
	})
	fromRow := container.NewBorder(nil, nil, nil, fromCalButton, fromEntry)

	// To date picker with "No expiry" checkbox.
	toEntry := widget.NewEntry()
	toEntry.Disable()
	toCalButton := widget.NewButton("\U0001F4C5", func() {
		cal := xwidget.NewCalendar(time.Now().UTC(), func(t time.Time) {
			toEntry.SetText(t.Format("2006-01-02"))
		})
		dialog.ShowCustom("Select Date", "Close", cal, window)
	})

	hasExpiry := entry.To != nil
	if hasExpiry {
		toEntry.SetText(*entry.To)
		toEntry.Enable()
		toCalButton.Enable()
	} else {
		toCalButton.Disable()
	}
	toRow := container.NewBorder(nil, nil, nil, toCalButton, toEntry)

	noExpiryCheck := widget.NewCheck("No expiry", func(checked bool) {
		if checked {
			toEntry.SetText("")
			toEntry.Disable()
			toCalButton.Disable()
		} else {
			toEntry.Enable()
			toCalButton.Enable()
		}
	})
	noExpiryCheck.SetChecked(!hasExpiry)

	// Public key is read-only for edit.
	keyLabel := widget.NewLabel(entry.PublicKey)
	keyLabel.Wrapping = fyne.TextWrapBreak

	noteEntry := widget.NewMultiLineEntry()
	noteEntry.SetText(entry.Note)

	formContent := container.NewVBox(
		widget.NewLabel("Authority"),
		authorityEntry,
		widget.NewLabel("From date"),
		fromRow,
		widget.NewLabel("To date"),
		toRow,
		noExpiryCheck,
		widget.NewLabel("Public Key"),
		keyLabel,
		widget.NewLabel("Note"),
		noteEntry,
	)

	dialog.ShowCustomConfirm("Edit Entry", "Save", "Cancel", formContent, func(ok bool) {
		if !ok {
			return
		}
		authority := strings.TrimSpace(authorityEntry.Text)
		if authority == "" {
			return
		}
		if fromEntry.Text == "" {
			return
		}

		var to *string
		if !noExpiryCheck.Checked && toEntry.Text != "" {
			t := toEntry.Text
			to = &t
		}

		updated := buildEntry(authorityEntry.Text, fromEntry.Text, to, entry.PublicKey, noteEntry.Text)
		onSave(updated)
	}, window)
}

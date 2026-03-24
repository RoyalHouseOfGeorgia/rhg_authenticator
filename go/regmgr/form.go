package regmgr

import (
	"fmt"
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
	"github.com/royalhouseofgeorgia/rhg-authenticator/yubikey"
	"golang.org/x/text/unicode/norm"
)

// buildEntry constructs a KeyEntry from form values.
func buildEntry(authority, from string, to *string, publicKey, note string) core.KeyEntry {
	return core.KeyEntry{
		Authority: norm.NFC.String(strings.TrimSpace(authority)),
		From:      from,
		To:        to,
		Algorithm: core.SupportedAlgorithm,
		PublicKey:  publicKey,
		Note:      note,
	}
}

// datePickerRow holds widgets for a date input with calendar button.
type datePickerRow struct {
	entry  *widget.Entry
	calBtn *widget.Button
	row    *fyne.Container
}

// newDatePickerRow builds a date picker row with a calendar popup.
func newDatePickerRow(window fyne.Window, initial string) datePickerRow {
	entry := widget.NewEntry()
	entry.SetText(initial)
	entry.Disable()
	calBtn := widget.NewButton("\U0001F4C5", func() {
		cal := xwidget.NewCalendar(time.Now().UTC(), func(t time.Time) {
			entry.SetText(t.Format("2006-01-02"))
		})
		dialog.ShowCustom("Select Date", "Close", cal, window)
	})
	row := container.NewBorder(nil, nil, nil, calBtn, entry)
	return datePickerRow{entry: entry, calBtn: calBtn, row: row}
}

// newExpirySection builds a to-date picker with "No expiry" checkbox.
func newExpirySection(window fyne.Window, initialTo string, hasExpiry bool) (datePickerRow, *widget.Check) {
	dp := newDatePickerRow(window, initialTo)
	if !hasExpiry {
		dp.calBtn.Disable()
	}
	noExpiryCheck := widget.NewCheck("No expiry", func(checked bool) {
		if checked {
			dp.entry.SetText("")
			dp.entry.Disable()
			dp.calBtn.Disable()
		} else {
			dp.entry.Enable()
			dp.calBtn.Enable()
		}
	})
	noExpiryCheck.SetChecked(!hasExpiry)
	return dp, noExpiryCheck
}

// validateEntryForm validates common entry form fields.
// Returns nil if valid, or an error with a user-facing message.
func validateEntryForm(authority, from, key string, noExpiry bool, to string) error {
	if strings.TrimSpace(authority) == "" {
		return fmt.Errorf("Authority is required")
	}
	if from == "" {
		return fmt.Errorf("From date is required")
	}
	if !core.IsValidDate(from) {
		return fmt.Errorf("Invalid from date format")
	}
	if !noExpiry && to != "" && !core.IsValidDate(to) {
		return fmt.Errorf("Invalid to date format")
	}
	if key == "" {
		return fmt.Errorf("Import a public key first")
	}
	return nil
}

// showAddDialog shows a dialog for adding a new key entry.
func showAddDialog(window fyne.Window, onAdd func(core.KeyEntry)) {
	authorityEntry := widget.NewEntry()
	authorityEntry.SetPlaceHolder("Authority name")

	fromDP := newDatePickerRow(window, time.Now().UTC().Format("2006-01-02"))
	toDP, noExpiryCheck := newExpirySection(window, "", false)

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

	importYubiKeyBtn := widget.NewButton("Import from YubiKey", func() {
		key, err := yubikey.ReadPublicKey()
		if err != nil {
			switch core.ClassifyHardwareError(err) {
			case core.HwErrSmartcard:
				keyLabel.SetText("Smart card service not available")
			default:
				keyLabel.SetText("No YubiKey detected — plug in and try again")
			}
			importedKey = ""
			errorLabel.SetText("")
			return
		}
		importedKey = key
		keyLabel.SetText(key)
		errorLabel.SetText("")
	})

	noteEntry := widget.NewMultiLineEntry()
	noteEntry.SetPlaceHolder("Optional note")

	formContent := container.NewVBox(
		widget.NewLabel("Authority"),
		authorityEntry,
		widget.NewLabel("From date"),
		fromDP.row,
		widget.NewLabel("To date"),
		toDP.row,
		noExpiryCheck,
		widget.NewLabel("Public Key"),
		container.NewHBox(importBtn, importYubiKeyBtn),
		keyLabel,
		errorLabel,
		widget.NewLabel("Note"),
		noteEntry,
	)

	dialog.ShowCustomConfirm("Add Entry", "Add", "Cancel", formContent, func(ok bool) {
		if !ok {
			return
		}
		if err := validateEntryForm(authorityEntry.Text, fromDP.entry.Text, importedKey, noExpiryCheck.Checked, toDP.entry.Text); err != nil {
			errorLabel.SetText(err.Error())
			return
		}

		var to *string
		if !noExpiryCheck.Checked && toDP.entry.Text != "" {
			t := toDP.entry.Text
			to = &t
		}

		entry := buildEntry(authorityEntry.Text, fromDP.entry.Text, to, importedKey, noteEntry.Text)
		onAdd(entry)
	}, window)
}

// showEditDialog shows a dialog for editing an existing key entry.
func showEditDialog(window fyne.Window, entry core.KeyEntry, onSave func(core.KeyEntry)) {
	authorityEntry := widget.NewEntry()
	authorityEntry.SetText(entry.Authority)

	fromDP := newDatePickerRow(window, entry.From)

	hasExpiry := entry.To != nil
	initialTo := ""
	if hasExpiry {
		initialTo = *entry.To
	}
	toDP, noExpiryCheck := newExpirySection(window, initialTo, hasExpiry)

	// Public key is read-only for edit.
	keyLabel := widget.NewLabel(entry.PublicKey)
	keyLabel.Wrapping = fyne.TextWrapBreak

	noteEntry := widget.NewMultiLineEntry()
	noteEntry.SetText(entry.Note)

	errorLabel := widget.NewLabel("")
	errorLabel.Wrapping = fyne.TextWrapBreak

	formContent := container.NewVBox(
		widget.NewLabel("Authority"),
		authorityEntry,
		widget.NewLabel("From date"),
		fromDP.row,
		widget.NewLabel("To date"),
		toDP.row,
		noExpiryCheck,
		widget.NewLabel("Public Key"),
		keyLabel,
		widget.NewLabel("Note"),
		noteEntry,
		errorLabel,
	)

	dialog.ShowCustomConfirm("Edit Entry", "Save", "Cancel", formContent, func(ok bool) {
		if !ok {
			return
		}
		if err := validateEntryForm(authorityEntry.Text, fromDP.entry.Text, entry.PublicKey, noExpiryCheck.Checked, toDP.entry.Text); err != nil {
			errorLabel.SetText(err.Error())
			return
		}

		var to *string
		if !noExpiryCheck.Checked && toDP.entry.Text != "" {
			t := toDP.entry.Text
			to = &t
		}

		updated := buildEntry(authorityEntry.Text, fromDP.entry.Text, to, entry.PublicKey, noteEntry.Text)
		onSave(updated)
	}, window)
}

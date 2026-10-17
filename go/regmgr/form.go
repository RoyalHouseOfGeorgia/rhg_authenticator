package regmgr

import (
	"errors"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
	xwidget "fyne.io/x/fyne/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/safego"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
)

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

// entryForm collects the entry dialog inputs.
func entryForm(authority *widget.Entry, from, to datePickerRow, noExpiry *widget.Check, note *widget.Entry) service.EntryForm {
	return service.EntryForm{
		Authority: authority.Text,
		From:      from.entry.Text,
		To:        to.entry.Text,
		Note:      note.Text,
		NoExpiry:  noExpiry.Checked,
	}
}

// showAddDialog shows a dialog for adding a new key entry; onAdded runs after
// svc accepted it.
func showAddDialog(window fyne.Window, svc *service.App, onAdded func()) {
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
				errorLabel.SetText(core.StripControlChars(err.Error()))
				return
			}
			if reader == nil {
				return // cancelled
			}
			defer reader.Close()

			key, err := svc.ImportCertificate(reader.URI().Path())
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
		safego.Go(func() {
			key, err := svc.ImportFromYubiKey()
			fyne.Do(func() {
				if errors.Is(err, service.ErrBusy) {
					return // another card operation is running; leave the current key alone
				}
				if err != nil {
					keyLabel.SetText(err.Error())
					importedKey = ""
					errorLabel.SetText("")
					return
				}
				importedKey = key
				keyLabel.SetText(key)
				errorLabel.SetText("")
			})
		})
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

	// Use NewCustomWithoutButtons + SetButtons so validation errors are
	// visible on the still-open dialog. ShowCustomConfirm dismisses the
	// dialog before invoking the callback, hiding any errorLabel updates.
	d := dialog.NewCustomWithoutButtons("Add Entry", formContent, window)

	confirmBtn := widget.NewButton("Add", func() {
		if err := svc.AddEntry(entryForm(authorityEntry, fromDP, toDP, noExpiryCheck, noteEntry), importedKey); err != nil {
			errorLabel.SetText(err.Error())
			return
		}
		d.Hide()
		onAdded()
	})
	confirmBtn.Importance = widget.HighImportance

	cancelBtn := widget.NewButton("Cancel", func() { d.Hide() })

	d.SetButtons([]fyne.CanvasObject{cancelBtn, confirmBtn})
	d.Show()
}

// showEditDialog shows a dialog for editing entry, the registry entry at
// index; onSaved runs after svc accepted the change.
func showEditDialog(window fyne.Window, svc *service.App, index int, entry core.KeyEntry, onSaved func()) {
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

	// Use NewCustomWithoutButtons + SetButtons so validation errors are
	// visible on the still-open dialog. ShowCustomConfirm dismisses the
	// dialog before invoking the callback, hiding any errorLabel updates.
	d := dialog.NewCustomWithoutButtons("Edit Entry", formContent, window)

	confirmBtn := widget.NewButton("Save", func() {
		if err := svc.UpdateEntry(index, entry.PublicKey, entryForm(authorityEntry, fromDP, toDP, noExpiryCheck, noteEntry)); err != nil {
			errorLabel.SetText(err.Error())
			return
		}
		d.Hide()
		onSaved()
	})
	confirmBtn.Importance = widget.HighImportance

	cancelBtn := widget.NewButton("Cancel", func() { d.Hide() })

	d.SetButtons([]fyne.CanvasObject{cancelBtn, confirmBtn})
	d.Show()
}

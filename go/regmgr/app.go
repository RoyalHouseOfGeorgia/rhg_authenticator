package regmgr

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
	"github.com/royalhouseofgeorgia/rhg-authenticator/gui"
	"github.com/royalhouseofgeorgia/rhg-authenticator/safego"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
)

// tableColumnWidths defines the minimum widths for each column of
// service.RegistryColumns().
var tableColumnWidths = []float32{40, 200, 100, 100, 150, 200, 450}

// RegistryTab is the registry manager UI on top of service.App. Its methods
// run on the Fyne main thread.
type RegistryTab struct {
	Content     fyne.CanvasObject
	svc         *service.App
	snap        service.RegistrySnapshot
	columns     []string // service.RegistryColumns()
	selected    int      // selected table row, -1 = none
	table       *widget.Table
	statusLabel *widget.Label
	loginBtn    *widget.Button
	window      fyne.Window
	loginDialog *dialog.CustomDialog
	// login runs App.Login in the background; a field so tests can stub it.
	login func()
}

// Fetch re-fetches the registry in the background; success arrives as
// EventRegistryChanged.
func (rt *RegistryTab) Fetch() {
	rt.statusLabel.SetText("Fetching...")
	safego.Go(func() {
		if err := rt.svc.FetchRegistry(context.Background()); err != nil {
			fyne.Do(func() { rt.statusLabel.SetText("Failed to load registry") })
		}
	})
}

// refreshTable re-reads the edited registry and redraws the table.
func (rt *RegistryTab) refreshTable() {
	rt.snap = rt.svc.Registry()
	rt.table.Refresh()
}

// registryChanged applies a fetched registry (EventRegistryChanged).
func (rt *RegistryTab) registryChanged() {
	rt.selected = -1
	rt.table.UnselectAll()
	rt.refreshTable()
	if rt.snap.Loaded {
		rt.statusLabel.SetText("Loaded from registry server")
	} else {
		rt.statusLabel.SetText("Failed to load registry")
	}
}

// UpdateLoginUI sets the login button text for st. The host calls it on
// every EventAuthChanged.
func (rt *RegistryTab) UpdateLoginUI(st service.AuthState) {
	if !st.LoggedIn {
		rt.loginBtn.SetText("Login to GitHub")
	} else if st.Offline {
		rt.loginBtn.SetText("Offline — Reconnect")
	} else {
		rt.loginBtn.SetText("@" + st.User + " ▾")
	}
}

// StartLogin is the single entry point for "log in" buttons: it starts
// App.Login, which reconnects a session that was offline or else runs the
// device authorization flow.
func (rt *RegistryTab) StartLogin() {
	rt.startLogin(rt.svc.AuthState())
}

// startLogin is StartLogin from login state st.
func (rt *RegistryTab) startLogin(st service.AuthState) {
	if st.LoggedIn && st.Offline {
		rt.statusLabel.SetText("Reconnecting to GitHub...")
	} else {
		rt.statusLabel.SetText("Requesting device code...")
	}
	rt.login()
}

// runLogin is the default login: App.Login in the background, then loginDone.
func (rt *RegistryTab) runLogin() {
	safego.Go(func() {
		st, err := rt.svc.Login(context.Background())
		fyne.Do(func() { rt.loginDone(st, err) })
	})
}

// loginDone shows the outcome of a Login.
func (rt *RegistryTab) loginDone(st service.AuthState, err error) {
	if errors.Is(err, service.ErrBusy) {
		rt.statusLabel.SetText("Login already in progress")
		return
	}
	rt.hideLoginDialog()
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			dialog.ShowError(err, rt.window)
		}
		rt.statusLabel.SetText("")
		return
	}
	if st.Offline {
		rt.statusLabel.SetText("")
		dialog.ShowInformation("GitHub Unreachable",
			"Still can't reach GitHub. Check your connection and try again.", rt.window)
		return
	}
	rt.statusLabel.SetText(st.StatusText())
}

// showLoginDialog displays the device code (EventAuthDeviceCode); Cancel
// stops the login.
func (rt *RegistryTab) showLoginDialog(dc service.DeviceCode) {
	rt.statusLabel.SetText("Waiting for GitHub authorization...")
	codeLabel := widget.NewLabel(dc.UserCode)
	codeLabel.TextStyle = fyne.TextStyle{Bold: true, Monospace: true}
	codeLabel.Alignment = fyne.TextAlignCenter

	copyBtn := widget.NewButton("Copy Code", func() {
		fyne.CurrentApp().Clipboard().SetContent(dc.UserCode)
	})
	openBtn := widget.NewButton("Open GitHub", func() {
		if u, err := url.Parse(dc.VerificationURI); err == nil {
			_ = fyne.CurrentApp().OpenURL(u)
		}
	})
	if dc.VerificationURI == "" {
		openBtn.Disable() // the code can still be copied and entered by hand
	}

	content := container.NewVBox(
		widget.NewLabel("Enter this code at GitHub:"),
		codeLabel,
		container.NewHBox(copyBtn, openBtn),
	)

	d := dialog.NewCustom("GitHub Login", "Cancel", content, rt.window)
	d.SetOnClosed(func() {
		if rt.loginDialog == d {
			rt.loginDialog = nil
			rt.svc.CancelLogin()
		}
	})
	rt.loginDialog = d
	d.Show()
}

// hideLoginDialog dismisses the device code dialog without cancelling.
func (rt *RegistryTab) hideLoginDialog() {
	if d := rt.loginDialog; d != nil {
		rt.loginDialog = nil
		d.Hide()
	}
}

// handleSubmitError shows the dialog for a SubmitRegistry error and, if the
// session expired (SubmitRegistry has already logged out), restarts login.
func (rt *RegistryTab) handleSubmitError(err error) {
	switch {
	case errors.Is(err, service.ErrSessionExpired):
		dialog.ShowInformation("Session Expired", err.Error(), rt.window)
		rt.StartLogin()
		return
	case errors.Is(err, service.ErrRegistryChanged):
		dialog.ShowInformation("Registry Changed", err.Error(), rt.window)
	default:
		gui.ShowErrorWithLogExport("Submission Failed", err.Error(), rt.svc.ErrorLogExport, rt.window)
	}
	rt.statusLabel.SetText("")
}

// handleSubmitSuccess shows the created pull request.
func (rt *RegistryTab) handleSubmitSuccess(pr service.SubmitResult) {
	rt.statusLabel.SetText(fmt.Sprintf("PR #%d created", pr.PRNumber))

	if prURL := ghapi.ParseGitHubURL(pr.URL); prURL != nil {
		dialog.ShowConfirm("Pull Request Created",
			fmt.Sprintf("PR #%d has been created.\n\nOpen in browser?", pr.PRNumber),
			func(ok bool) {
				if ok {
					_ = fyne.CurrentApp().OpenURL(prURL)
				}
			}, rt.window)
	} else {
		dialog.ShowInformation("Pull Request Created",
			fmt.Sprintf("PR #%d has been created.", pr.PRNumber), rt.window)
	}
}

// submitForReview opens a GitHub pull request with the edited registry,
// logging in (or reconnecting) first if there is no usable session.
func (rt *RegistryTab) submitForReview() {
	if len(rt.snap.Entries) == 0 {
		return
	}
	rt.statusLabel.SetText("Creating pull request...")
	safego.Go(func() {
		pr, err := rt.svc.SubmitRegistry(context.Background())
		fyne.Do(func() {
			switch {
			case errors.Is(err, service.ErrNotLoggedIn):
				rt.StartLogin()
			case errors.Is(err, service.ErrBusy):
				rt.statusLabel.SetText("Submit already in progress")
			case err != nil:
				rt.handleSubmitError(err)
			default:
				rt.handleSubmitSuccess(pr)
			}
		})
	})
}

// NewRegistryTab creates the registry manager UI as a tab on top of svc,
// whose events arrive through events. The caller owns the window — this does
// not set close intercepts or change the window title.
func NewRegistryTab(svc *service.App, events *gui.Events, window fyne.Window) *RegistryTab {
	rt := &RegistryTab{
		svc:         svc,
		columns:     service.RegistryColumns(),
		selected:    -1,
		statusLabel: widget.NewLabel(""),
		window:      window,
	}
	rt.login = rt.runLogin

	rt.table = widget.NewTable(
		func() (int, int) {
			return len(rt.snap.Rows) + 1, len(rt.columns) // +1 for header row
		},
		func() fyne.CanvasObject {
			label := widget.NewLabel("placeholder")
			label.Truncation = fyne.TextTruncateEllipsis
			return label
		},
		func(id widget.TableCellID, o fyne.CanvasObject) {
			label, ok := o.(*widget.Label)
			if !ok {
				return
			}
			label.Truncation = fyne.TextTruncateEllipsis
			if id.Row == 0 {
				// Header row.
				label.SetText(rt.columns[id.Col])
				label.TextStyle = fyne.TextStyle{Bold: true}
				return
			}
			label.TextStyle = fyne.TextStyle{}
			label.SetText(rt.snap.Rows[id.Row-1][id.Col])
		},
	)
	for i, w := range tableColumnWidths {
		rt.table.SetColumnWidth(i, w)
	}
	rt.table.OnSelected = func(id widget.TableCellID) {
		if id.Row == 0 {
			// Header row — ignore.
			rt.table.UnselectAll()
			return
		}
		rt.selected = id.Row - 1 // 0-based index into the entries
		if rt.selected < len(rt.snap.Rows) {
			if cellText := rt.snap.Rows[rt.selected][id.Col]; cellText != "" {
				rt.statusLabel.SetText(cellText)
			}
		}
	}

	// Login button — text changes based on auth state.
	rt.loginBtn = widget.NewButton("Login to GitHub", func() {
		if st := svc.AuthState(); !st.LoggedIn || st.Offline {
			rt.StartLogin()
			return
		}
		dialog.ShowConfirm("Log Out",
			"Log out of GitHub? You'll need to re-authorize to submit future updates.",
			func(ok bool) {
				if !ok {
					return
				}
				svc.Logout()
				rt.statusLabel.SetText("Logged out")
			}, window)
	})

	// Toolbar buttons.
	fetchBtn := widget.NewButton("Fetch from Server", func() {
		if svc.Dirty() {
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

	submitBtn := widget.NewButton("Submit for Review", rt.submitForReview)

	toolbar := container.NewHBox(
		fetchBtn, submitBtn,
		layout.NewSpacer(),
		rt.loginBtn,
		rt.statusLabel,
	)

	// Action bar buttons.
	addBtn := widget.NewButton("Add Entry", func() {
		showAddDialog(window, svc, rt.refreshTable)
	})

	editBtn := widget.NewButton("Edit Entry", func() {
		if rt.selected < 0 || rt.selected >= len(rt.snap.Entries) {
			dialog.ShowInformation("Edit Entry", "No entry selected", window)
			return
		}
		showEditDialog(window, svc, rt.selected, rt.snap.Entries[rt.selected], rt.refreshTable)
	})

	// No Remove button — the registry is a system of record.
	// To revoke a key, edit the entry and set an expiry date.

	actionBar := container.NewHBox(addBtn, editBtn)

	rt.Content = container.NewBorder(toolbar, actionBar, nil, nil, rt.table)

	// Register first, then read state, so a change that fired before
	// registration is not missed. svc.Start loads the registry once the
	// session restore is known. The host handles EventAuthChanged (see
	// UpdateLoginUI).
	events.On(service.EventAuthDeviceCode, func(p any) {
		if dc, ok := p.(service.DeviceCode); ok {
			rt.showLoginDialog(dc)
		}
	})
	events.On(service.EventRegistryChanged, func(any) { rt.registryChanged() })
	rt.UpdateLoginUI(svc.AuthState())
	rt.refreshTable()
	if rt.snap.Loaded {
		rt.statusLabel.SetText("Loaded from registry server")
	} else {
		rt.statusLabel.SetText("Fetching...")
	}

	return rt
}

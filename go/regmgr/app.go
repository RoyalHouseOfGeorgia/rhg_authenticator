package regmgr

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
	"github.com/royalhouseofgeorgia/rhg-authenticator/registry"
)

// appState holds the mutable state for the registry manager UI.
// All fields are mutated exclusively inside fyne.Do() callbacks (main goroutine).
// atomic.Bool fields on RegistryTab are belt-and-suspenders guards.
type appState struct {
	registry    core.Registry
	filePath    string // "" = not yet saved locally
	dirty       bool
	selected    int // selected table row, -1 = none
	githubToken ghapi.Token
	loggedIn    bool
	offline     bool
	githubUser  string
}

// tableColumns defines the column headers for the registry table.
var tableColumns = []string{"#", "Authority", "From", "To", "Note", "Fingerprint"}

// tableColumnWidths defines the minimum widths for each table column.
var tableColumnWidths = []float32{40, 200, 100, 100, 200, 450}

// canSave returns whether the registry has entries that can be saved.
func canSave(reg core.Registry) bool {
	return len(reg.Keys) > 0
}

// RegistryTab holds the registry manager UI and its state.
type RegistryTab struct {
	Content      fyne.CanvasObject
	state        *appState
	table        *widget.Table
	statusLabel  *widget.Label
	loginBtn     *widget.Button
	window       fyne.Window
	rebuildCache func()
	configDir    string
	kr           ghapi.Keyring
	submitting   atomic.Bool
	loggingIn    atomic.Bool
}

// IsDirty returns whether the registry has unsubmitted changes.
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
			if rt.rebuildCache != nil { // nil during tests without full init
				rt.rebuildCache()
			}
			rt.table.Refresh()
			rt.statusLabel.SetText("Loaded from registry server")
		})
	}()
}

// resolveLoginState determines the login display state from validation results.
// Pure function — no side effects, no ghapi dependency in the body.
func resolveLoginState(isUnauthorized bool, username string, hasError bool) (loggedIn, offline bool, statusText string) {
	if isUnauthorized {
		return false, false, "Not logged in"
	}
	if hasError {
		return true, true, "Logged in (offline)"
	}
	return true, false, "Logged in as @" + username
}

// updateLoginUI updates the login button text to reflect current auth state.
// Must be called from the Fyne main thread (inside fyne.Do or during construction).
func (rt *RegistryTab) updateLoginUI() {
	if !rt.state.loggedIn {
		rt.loginBtn.SetText("Login to GitHub")
	} else if rt.state.offline {
		rt.loginBtn.SetText("Logged in (offline)")
	} else {
		rt.loginBtn.SetText("@" + rt.state.githubUser + " \u25BE")
	}
}

// handleDeviceCodeError shows an error dialog when RequestDeviceCode fails
// and clears the status label. Must be called on the Fyne main thread.
func (rt *RegistryTab) handleDeviceCodeError(ctx context.Context, err error) {
	if ctx.Err() == nil {
		dialog.ShowError(fmt.Errorf("device code request failed: %w", err), rt.window)
	}
	rt.statusLabel.SetText("")
}

// handlePollError shows an error dialog when PollForToken fails
// and clears the status label. Must be called on the Fyne main thread.
func (rt *RegistryTab) handlePollError(ctx context.Context, err error) {
	if ctx.Err() == nil {
		dialog.ShowError(fmt.Errorf("login failed: %w", err), rt.window)
	}
	rt.statusLabel.SetText("")
}

// completeLogin saves the token, updates UI state via resolveLoginState,
// and cancels the login context. Must be called on the Fyne main thread.
func (rt *RegistryTab) completeLogin(tok ghapi.Token, username string, valErr error, cancel context.CancelFunc) {
	loggedIn, offline, statusText := resolveLoginState(
		ghapi.IsUnauthorized(valErr), username, valErr != nil,
	)
	if loggedIn {
		rt.state.githubToken = tok
	} else {
		rt.state.githubToken = ghapi.Token{}
	}
	rt.state.loggedIn = loggedIn
	rt.state.offline = offline
	rt.state.githubUser = username
	rt.statusLabel.SetText(statusText)
	rt.updateLoginUI()
	cancel()
}

// startLogin initiates the GitHub device authorization flow.
// The loggingIn atomic is belt-and-suspenders over Fyne UI thread serialization.
// Primary serialization is the Fyne main thread; the atomic is a safety net
// for the submitForReview → startLogin re-entry path.
func (rt *RegistryTab) startLogin() {
	if !rt.loggingIn.CompareAndSwap(false, true) {
		rt.statusLabel.SetText("Login already in progress")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	rt.statusLabel.SetText("Requesting device code...")

	go func() {
		defer rt.loggingIn.Store(false)
		dcr, err := ghapi.RequestDeviceCode(ctx)
		if err != nil {
			fyne.Do(func() { rt.handleDeviceCodeError(ctx, err) })
			cancel()
			return
		}

		fyne.Do(func() {
			rt.statusLabel.SetText("Waiting for GitHub authorization...")
			rt.showLoginDialog(ctx, cancel, dcr)
		})

		// PollForToken always sleeps one full interval (minimum 5 seconds) before its
		// first network call, which is ample time for fyne.Do to render the dialog above.
		tok, pollErr := ghapi.PollForToken(ctx, dcr.DeviceCode, dcr.Interval, dcr.ExpiresIn)
		if pollErr != nil {
			fyne.Do(func() { rt.handlePollError(ctx, pollErr) })
			cancel()
			return
		}

		// Validate token to get username before persisting.
		valCtx, valCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer valCancel()
		username, valErr := ghapi.ValidateToken(valCtx, tok)
		if valErr != nil {
			log.Printf("warning: token validation failed: %v", valErr)
		}

		// Save token only if validation didn't return 401 (unauthorized).
		if !ghapi.IsUnauthorized(valErr) {
			if saveErr := ghapi.SaveToken(rt.kr, rt.configDir, tok); saveErr != nil {
				log.Printf("warning: failed to save token: %v", saveErr)
			}
		}

		fyne.Do(func() { rt.completeLogin(tok, username, valErr, cancel) })
	}()
}

// showLoginDialog displays the device code dialog for user interaction.
func (rt *RegistryTab) showLoginDialog(ctx context.Context, cancel context.CancelFunc, dcr ghapi.DeviceCodeResponse) {
	codeLabel := widget.NewLabel(dcr.UserCode)
	codeLabel.TextStyle = fyne.TextStyle{Bold: true, Monospace: true}
	codeLabel.Alignment = fyne.TextAlignCenter

	copyBtn := widget.NewButton("Copy Code", func() {
		rt.window.Clipboard().SetContent(dcr.UserCode)
	})

	parsedURL, urlErr := url.Parse(dcr.VerificationURI)
	openBtn := widget.NewButton("Open GitHub", func() {
		if parsedURL != nil {
			_ = fyne.CurrentApp().OpenURL(parsedURL)
		}
	})
	if urlErr != nil || parsedURL == nil || parsedURL.Scheme != "https" || parsedURL.Host != "github.com" {
		openBtn.Disable()
		log.Printf("warning: invalid verification URI: %s", dcr.VerificationURI)
	}

	content := container.NewVBox(
		widget.NewLabel("Enter this code at GitHub:"),
		codeLabel,
		container.NewHBox(copyBtn, openBtn),
	)

	d := dialog.NewCustom("GitHub Login", "Cancel", content, rt.window)
	d.SetOnClosed(func() {
		cancel()
	})
	d.Show()

	// Dismiss dialog automatically when polling completes.
	go func() {
		<-ctx.Done()
		fyne.Do(func() {
			d.Hide()
		})
	}()
}

// userFacingError maps API errors to safe, user-friendly messages.
func userFacingError(err error) string {
	if ghapi.IsRateLimited(err) {
		return "GitHub rate limit reached. Try again in a few minutes."
	}
	if ghapi.IsForbidden(err) {
		return "Permission denied. Check your GitHub account permissions."
	}
	// Network/timeout errors
	return "An error occurred. Please try again later."
}

// handleSubmitError handles PR creation errors — shows a dialog and, if the
// token is unauthorized, clears it and restarts login.
// Must be called on the Fyne main thread.
func (rt *RegistryTab) handleSubmitError(err error) {
	if ghapi.IsUnauthorized(err) {
		_ = ghapi.ClearToken(rt.kr, rt.configDir)
		rt.state.loggedIn = false
		rt.state.githubToken = ghapi.Token{}
		rt.state.githubUser = ""
		rt.updateLoginUI()
		rt.statusLabel.SetText("Session expired. Please log in again.")
		rt.startLogin()
	} else {
		log.Printf("error: PR submission failed: %v", err)
		dialog.ShowError(fmt.Errorf("%s", userFacingError(err)), rt.window)
		rt.statusLabel.SetText("")
	}
}

// handleSubmitSuccess parses the PR URL and shows a success dialog.
// Must be called on the Fyne main thread.
func (rt *RegistryTab) handleSubmitSuccess(pr ghapi.PRResult) {
	rt.state.dirty = false
	rt.statusLabel.SetText(fmt.Sprintf("PR #%d created", pr.Number))

	prURL, urlErr := url.Parse(pr.HTMLURL)
	if urlErr == nil && prURL.Scheme == "https" {
		dialog.ShowConfirm("Pull Request Created",
			fmt.Sprintf("PR #%d has been created.\n\nOpen in browser?", pr.Number),
			func(ok bool) {
				if ok {
					_ = fyne.CurrentApp().OpenURL(prURL)
				}
			}, rt.window)
	} else {
		dialog.ShowInformation("Pull Request Created",
			fmt.Sprintf("PR #%d has been created.", pr.Number), rt.window)
	}
}

// submitForReview marshals the registry and creates a GitHub pull request.
func (rt *RegistryTab) submitForReview() {
	if !canSave(rt.state.registry) {
		return
	}
	if !rt.state.loggedIn {
		rt.startLogin()
		return
	}
	if !rt.submitting.CompareAndSwap(false, true) {
		return // already submitting
	}

	// Marshal inside fyne.Do to avoid sharing the registry slice/pointer fields
	// with the background goroutine. []byte is immutable once created.
	fyne.Do(func() {
		content, err := MarshalRegistry(rt.state.registry)
		if err != nil {
			rt.submitting.Store(false)
			dialog.ShowError(fmt.Errorf("marshal failed: %w", err), rt.window)
			return
		}
		token := rt.state.githubToken.AccessToken
		rt.statusLabel.SetText("Creating pull request...")

		go func() {
			defer rt.submitting.Store(false)

			submitCtx, submitCancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer submitCancel()

			client := ghapi.NewClient(token)
			pr, err := client.CreateRegistryPR(submitCtx, content, "Registry update")
			if err != nil {
				fyne.Do(func() { rt.handleSubmitError(err) })
				return
			}

			fyne.Do(func() { rt.handleSubmitSuccess(pr) })
		}()
	})
}

// entryCellText returns the display text for a registry table cell.
// entryIdx is the 0-based index into registry.Keys.
func entryCellText(entry core.KeyEntry, col, entryIdx int, fpCache map[int]string) string {
	switch col {
	case 0:
		return fmt.Sprintf("%d", entryIdx+1)
	case 1:
		return entry.Authority
	case 2:
		return core.FormatDateDisplay(entry.From)
	case 3:
		if entry.To != nil {
			return core.FormatDateDisplay(*entry.To)
		}
		return "(none)"
	case 4:
		return entry.Note
	case 5:
		if fp, ok := fpCache[entryIdx]; ok {
			return fp
		}
		return "(invalid key)"
	default:
		return ""
	}
}

// NewRegistryTab creates the registry manager UI as a tab.
// The caller owns the window — this does not set close intercepts or change the window title.
func NewRegistryTab(window fyne.Window, configDir string) *RegistryTab {
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
				label.SetText(tableColumns[id.Col])
				label.TextStyle = fyne.TextStyle{Bold: true}
				return
			}
			label.TextStyle = fyne.TextStyle{}
			entry := state.registry.Keys[id.Row-1]
			label.SetText(entryCellText(entry, id.Col, id.Row-1, fingerprintCache))
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
		if id.Row > 0 && id.Row-1 < len(state.registry.Keys) {
			entry := state.registry.Keys[id.Row-1]
			cellText := entryCellText(entry, id.Col, id.Row-1, fingerprintCache)
			if cellText != "" {
				statusLabel.SetText(cellText)
			}
		}
	}

	// Helper to refresh UI after state changes.
	refreshUI := func() {
		rebuildFingerprintCache()
		table.Refresh()
	}

	kr := ghapi.NewOSKeyring()

	rt := &RegistryTab{
		state:        state,
		table:        table,
		statusLabel:  statusLabel,
		window:       window,
		rebuildCache: rebuildFingerprintCache,
		configDir:    configDir,
		kr:           kr,
	}

	// Login button — text changes based on auth state.
	loginBtn := widget.NewButton("Login to GitHub", func() {
		if rt.state.loggedIn {
			dialog.ShowConfirm("Log Out",
				"Log out of GitHub? You'll need to re-authorize to submit future updates.",
				func(ok bool) {
					if !ok {
						return
					}
					_ = ghapi.ClearToken(rt.kr, rt.configDir)
					rt.state.loggedIn = false
					rt.state.offline = false
					rt.state.githubToken = ghapi.Token{}
					rt.state.githubUser = ""
					rt.updateLoginUI()
					rt.statusLabel.SetText("Logged out")
				}, window)
		} else {
			rt.startLogin()
		}
	})
	rt.loginBtn = loginBtn

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

	submitBtn := widget.NewButton("Submit for Review", func() {
		rt.submitForReview()
	})

	toolbar := container.NewHBox(
		fetchBtn, submitBtn,
		layout.NewSpacer(),
		loginBtn,
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

	// Async token restore.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		tok, username, loggedIn, offline, err := ghapi.RestoreSession(ctx, rt.kr, rt.configDir)
		if err != nil {
			log.Printf("warning: token restore failed: %v", err)
		}
		fyne.Do(func() {
			rt.state.githubToken = tok
			rt.state.loggedIn = loggedIn
			rt.state.offline = offline
			rt.state.githubUser = username
			rt.updateLoginUI()
		})
	}()

	return rt
}

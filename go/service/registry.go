package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/text/unicode/norm"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
	"github.com/royalhouseofgeorgia/rhg-authenticator/registry"
)

// ErrRegistryChanged is returned by SubmitRegistry when upstream's registry no
// longer matches the snapshot the local edits were based on (or none was loaded).
var ErrRegistryChanged = errors.New("registry on GitHub does not match the loaded snapshot")

// fetchRegistry loads the registry from main via the GitHub API when a client
// is available, so the submit check compares like with like and isn't tripped
// by the Pages deploy lag after a merge. Logged out (or if the API read fails)
// it falls back to the published Pages copy.
func (a *App) fetchRegistry(ctx context.Context, client *ghapi.Client) (core.Registry, error) {
	if client != nil {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		up, err := client.FetchUpstreamFile(ctx, ghapi.RegistryFilePath)
		if err == nil {
			return core.ValidateRegistry(up)
		}
		a.logger.Logf("warning: registry fetch from GitHub failed, using site copy: %s", core.SanitizeForLog(err.Error()))
	}
	return registry.FetchRegistry(a.registryURL)
}

// IsSafeGitHubURL checks whether a URL points to GitHub over HTTPS and is safe to open.
func IsSafeGitHubURL(rawURL string) (*url.URL, bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, false
	}
	return u, u.Scheme == "https" && ghapi.IsGitHubHost(u.Host)
}

// submitIfUnchanged refuses to open a PR if upstream's registry no longer matches
// the snapshot the edits were based on (base), so a stale fetch can't silently
// undo another change. Both sides go through marshalRegistry, so whitespace and
// line endings don't matter.
func submitIfUnchanged(ctx context.Context, client *ghapi.Client, base, content []byte, title string) (ghapi.PRResult, error) {
	up, err := client.FetchUpstreamFile(ctx, ghapi.RegistryFilePath)
	if err != nil {
		return ghapi.PRResult{}, fmt.Errorf("fetching upstream registry: %w", err)
	}
	reg, err := core.ValidateRegistry(up)
	if err != nil {
		return ghapi.PRResult{}, fmt.Errorf("validating upstream registry: %w", err)
	}
	upBytes, err := marshalRegistry(reg)
	if err != nil {
		return ghapi.PRResult{}, fmt.Errorf("re-marshaling upstream registry: %w", err)
	}
	if len(base) == 0 || !bytes.Equal(upBytes, base) {
		return ghapi.PRResult{}, ErrRegistryChanged
	}
	return client.CreateRegistryPR(ctx, content, title)
}

// restrictionsText renders a key's allowed_honors using the same rules as
// the verify page (src/registry.ts): "(none)" when unrestricted (absent,
// null, [] or all blank), "(invalid)" when the verify page would reject it,
// otherwise the non-blank honors joined by ", ".
func restrictionsText(entry core.KeyEntry) string {
	raw, ok := entry.Extra["allowed_honors"]
	if !ok {
		return "(none)"
	}
	var items []any
	if err := json.Unmarshal(raw, &items); err != nil {
		return "(invalid)"
	}
	kept := make([]string, 0, len(items))
	for _, item := range items {
		h, isString := item.(string)
		if !isString {
			return "(invalid)"
		}
		if core.StripControlChars(h) != h {
			return "(invalid)"
		}
		trimmed := core.TrimJS(h)
		if trimmed == "" {
			continue
		}
		if h != trimmed {
			return "(invalid)"
		}
		kept = append(kept, h)
	}
	if len(kept) == 0 {
		return "(none)"
	}
	return strings.Join(kept, ", ")
}

// entryCellText returns the display text for column col of entry, the
// entryIdx-th (0-based) key; fp is its fingerprint, "" if the key is invalid.
func entryCellText(entry core.KeyEntry, col, entryIdx int, fp string) string {
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
		return restrictionsText(entry)
	case 5:
		return entry.Note
	case 6:
		if fp != "" {
			return fp
		}
		return "(invalid key)"
	default:
		return ""
	}
}

// importKeyErrorMessage maps a YubiKey read error to a user-facing message for the
// "Import from YubiKey" flow.
func importKeyErrorMessage(err error) string {
	switch core.ClassifyHardwareError(err) {
	case core.HwErrSmartcard:
		return "Smart card service not available"
	case core.HwErrTransient:
		return core.MsgYubiKeyReset
	default:
		return "No YubiKey detected — plug in and try again"
	}
}

// buildEntry constructs a KeyEntry from form values.
func buildEntry(authority, from string, to *string, publicKey, note string) core.KeyEntry {
	return core.KeyEntry{
		Authority: norm.NFC.String(strings.TrimSpace(authority)),
		From:      from,
		To:        to,
		Algorithm: core.SupportedAlgorithm,
		PublicKey: publicKey,
		Note:      note,
	}
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
	if !noExpiry && to == "" {
		return fmt.Errorf("To date is required when 'No expiry' is not checked")
	}
	if !noExpiry && to != "" && !core.IsValidDate(to) {
		return fmt.Errorf("Invalid to date format")
	}
	// To may be before From: from is informational, and revoking a key
	// registered with a future From sets To to today.
	if key == "" {
		return fmt.Errorf("Import a public key first")
	}
	return nil
}

// EntryForm holds the add/edit entry dialog inputs.
type EntryForm struct {
	Authority, From, To, Note string
	NoExpiry                  bool
}

// RegistrySnapshot is a copy of the registry being edited. Rows[i] holds the
// table cell texts for Entries[i]; Loaded is false until a fetch succeeds.
type RegistrySnapshot struct {
	Entries       []core.KeyEntry
	Rows          [][]string
	Dirty, Loaded bool
}

// RegistryColumns are the table column headers; RegistrySnapshot.Rows cells
// follow this order.
var RegistryColumns = []string{"#", "Authority", "From", "To", "Restrictions", "Note", "Fingerprint"}

// Registry returns a copy of the registry being edited.
func (a *App) Registry() RegistrySnapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	rows := make([][]string, len(a.edit.Keys))
	for i, key := range a.edit.Keys {
		fp, _ := core.KeyFingerprint(key)
		rows[i] = make([]string, len(RegistryColumns))
		for col := range rows[i] {
			rows[i][col] = entryCellText(key, col, i, fp)
		}
	}
	return RegistrySnapshot{
		Entries: append([]core.KeyEntry(nil), a.edit.Keys...),
		Rows:    rows,
		Dirty:   a.dirty,
		Loaded:  a.baseBytes != nil,
	}
}

// FetchRegistry replaces the edited registry with the live one (from main via
// the API when logged in and online, else the published copy), discarding
// local edits, and emits EventRegistryChanged.
func (a *App) FetchRegistry(ctx context.Context) error {
	a.mu.Lock()
	client := a.clientLocked()
	a.mu.Unlock()
	reg, err := a.fetchRegistry(ctx, client)
	var base []byte
	if err == nil {
		base, err = marshalRegistry(reg)
	}
	if err != nil {
		a.logger.Logf("error: registry fetch failed: %s", core.SanitizeForLog(err.Error()))
		return err
	}
	a.mu.Lock()
	a.edit, a.baseBytes, a.dirty = reg, base, false
	a.mu.Unlock()
	a.events.Emit(EventRegistryChanged, nil)
	return nil
}

// entry validates f and builds the entry it describes.
func (f EntryForm) entry(publicKey string) (core.KeyEntry, error) {
	if err := validateEntryForm(f.Authority, f.From, publicKey, f.NoExpiry, f.To); err != nil {
		return core.KeyEntry{}, err
	}
	var to *string
	if !f.NoExpiry && f.To != "" {
		t := f.To
		to = &t
	}
	return buildEntry(f.Authority, f.From, to, publicKey, f.Note), nil
}

// AddEntry validates f and appends a new entry for publicKey. The error text
// is user-facing.
func (a *App) AddEntry(f EntryForm, publicKey string) error {
	e, err := f.entry(publicKey)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.edit.Keys = append(a.edit.Keys, e)
	a.dirty = true
	a.mu.Unlock()
	return nil
}

// UpdateEntry validates f and replaces entry index, keeping its extra fields.
// publicKey is the entry's key as shown to the user; if it no longer matches,
// a fetch replaced the list and the update is refused. The error text is
// user-facing.
func (a *App) UpdateEntry(index int, publicKey string, f EntryForm) error {
	e, err := f.entry(publicKey)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if index < 0 || index >= len(a.edit.Keys) || a.edit.Keys[index].PublicKey != publicKey {
		return errors.New("The registry was reloaded while you were editing. Cancel and edit the entry again.")
	}
	e.Extra = a.edit.Keys[index].Extra
	a.edit.Keys[index] = e
	a.dirty = true
	return nil
}

// Dirty reports whether there are unsubmitted registry edits.
func (a *App) Dirty() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.dirty
}

// ImportCertificate returns the base64 Ed25519 public key of the certificate
// (.crt/.pem) at path. The error text is user-facing.
func (a *App) ImportCertificate(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", errors.New("Failed to read file: " + core.StripControlChars(err.Error()))
	}
	key, err := extractEd25519Key(data)
	if err != nil {
		return "", errors.New(core.StripControlChars(err.Error()))
	}
	return key, nil
}

// ImportFromYubiKey returns the inserted YubiKey's base64 public key. The
// error text is user-facing, except ErrBusy.
func (a *App) ImportFromYubiKey() (string, error) {
	if !a.busy.CompareAndSwap(false, true) {
		return "", ErrBusy
	}
	defer a.busy.Store(false)

	key, err := a.readPublicKey()
	if err != nil {
		a.logger.Log("yubikey import: " + core.SanitizeForLog(err.Error()))
		return "", errors.New(importKeyErrorMessage(err))
	}
	return key, nil
}

// readPublicKey reads the slot-9c public key; no PIN is needed.
func (a *App) readPublicKey() (string, error) {
	adapter, closer, err := a.openAdapter(func() (string, error) { return "", nil })
	if err != nil {
		return "", err
	}
	defer closer.Close()
	pub, err := adapter.ExportPublicKey()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub[:]), nil
}

// SubmitRegistry opens a pull request with the edited registry and clears
// the unsubmitted flag on success, unless the registry was edited while the
// request ran. It returns ErrNotLoggedIn without a usable session, ErrBusy
// while another submit runs, an error matching ErrRegistryChanged when main
// moved since the fetch, and a GitHub error detectable with
// ghapi.IsUnauthorized when the session expired (it then logs out). Failures
// are logged; SubmitErrorMessage gives the text to show.
func (a *App) SubmitRegistry(ctx context.Context) (ghapi.PRResult, error) {
	if !a.submitting.CompareAndSwap(false, true) {
		return ghapi.PRResult{}, ErrBusy
	}
	defer a.submitting.Store(false)

	a.mu.Lock()
	canSave, client, base := len(a.edit.Keys) > 0, a.clientLocked(), a.baseBytes
	var content []byte
	var err error
	if canSave && client != nil {
		content, err = marshalRegistry(a.edit)
	}
	a.mu.Unlock()
	switch {
	case !canSave:
		return ghapi.PRResult{}, errors.New("the registry has no entries to submit")
	case client == nil:
		return ghapi.PRResult{}, ErrNotLoggedIn
	case err != nil:
		return ghapi.PRResult{}, fmt.Errorf("marshal failed: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	pr, err := submitIfUnchanged(ctx, client, base, content, "Registry update")
	switch {
	case ghapi.IsUnauthorized(err):
		a.logger.Logf("warning: registry submit unauthorized, logging out: %s", core.SanitizeForLog(err.Error()))
		a.Logout()
		return ghapi.PRResult{}, err
	case errors.Is(err, ErrRegistryChanged):
		a.logger.Logf("warning: registry submit refused: %s", core.SanitizeForLog(err.Error()))
		return ghapi.PRResult{}, err
	case err != nil:
		a.logger.Logf("error: PR submission failed: %s", core.SanitizeForLog(err.Error()))
		return ghapi.PRResult{}, err
	}
	a.mu.Lock()
	// Edits made while the request ran are not in the PR; keep them unsubmitted.
	if cur, err := marshalRegistry(a.edit); err == nil && bytes.Equal(cur, content) {
		a.dirty = false
	}
	a.mu.Unlock()
	return pr, nil
}

// SubmitErrorMessage returns the dialog title and message for a
// SubmitRegistry error.
func SubmitErrorMessage(err error) (title, msg string) {
	if ghapi.IsUnauthorized(err) {
		return "Session Expired", "Your GitHub session expired. Log in again, then submit again."
	}
	if errors.Is(err, ErrRegistryChanged) {
		return "Registry Changed", "The registry on GitHub doesn't match the copy you loaded (it changed, or nothing was loaded). Click Fetch from Server, re-apply your edits, and submit again."
	}
	return "Submission Failed", ghapi.UserMessage(err)
}

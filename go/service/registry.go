package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
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

// CanSave returns whether the registry has entries that can be saved.
func CanSave(reg core.Registry) bool {
	return len(reg.Keys) > 0
}

// FetchRegistry loads the registry from main via the GitHub API when a client
// is available, so the submit check compares like with like and isn't tripped
// by the Pages deploy lag after a merge. Logged out (or if the API read fails)
// it falls back to the published Pages copy.
func FetchRegistry(client *ghapi.Client) (core.Registry, error) {
	if client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		up, err := client.FetchUpstreamFile(ctx, ghapi.RegistryFilePath)
		if err == nil {
			return core.ValidateRegistry(up)
		}
		log.Printf("warning: registry fetch from GitHub failed, using site copy: %s", core.SanitizeForLog(err.Error()))
	}
	return registry.FetchRegistry(registry.DefaultRegistryURL)
}

// IsSafeGitHubURL checks whether a URL points to GitHub over HTTPS and is safe to open.
func IsSafeGitHubURL(rawURL string) (*url.URL, bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, false
	}
	return u, u.Scheme == "https" && ghapi.IsGitHubHost(u.Host)
}

// SubmitRegistry refuses to open a PR if upstream's registry no longer matches
// the snapshot the edits were based on (base), so a stale fetch can't silently
// undo another change. Both sides go through MarshalRegistry, so whitespace and
// line endings don't matter.
func SubmitRegistry(ctx context.Context, client *ghapi.Client, base, content []byte, title string) (ghapi.PRResult, error) {
	up, err := client.FetchUpstreamFile(ctx, ghapi.RegistryFilePath)
	if err != nil {
		return ghapi.PRResult{}, fmt.Errorf("fetching upstream registry: %w", err)
	}
	reg, err := core.ValidateRegistry(up)
	if err != nil {
		return ghapi.PRResult{}, fmt.Errorf("validating upstream registry: %w", err)
	}
	upBytes, err := MarshalRegistry(reg)
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

// EntryCellText returns the display text for a registry table cell.
// entryIdx is the 0-based index into registry.Keys.
func EntryCellText(entry core.KeyEntry, col, entryIdx int, fpCache map[int]string) string {
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
		if fp, ok := fpCache[entryIdx]; ok {
			return fp
		}
		return "(invalid key)"
	default:
		return ""
	}
}

// ImportKeyErrorMessage maps a YubiKey read error to a user-facing message for the
// "Import from YubiKey" flow.
func ImportKeyErrorMessage(err error) string {
	switch core.ClassifyHardwareError(err) {
	case core.HwErrSmartcard:
		return "Smart card service not available"
	case core.HwErrTransient:
		return core.MsgYubiKeyReset
	default:
		return "No YubiKey detected — plug in and try again"
	}
}

// BuildEntry constructs a KeyEntry from form values.
func BuildEntry(authority, from string, to *string, publicKey, note string) core.KeyEntry {
	return core.KeyEntry{
		Authority: norm.NFC.String(strings.TrimSpace(authority)),
		From:      from,
		To:        to,
		Algorithm: core.SupportedAlgorithm,
		PublicKey: publicKey,
		Note:      note,
	}
}

// ValidateEntryForm validates common entry form fields.
// Returns nil if valid, or an error with a user-facing message.
func ValidateEntryForm(authority, from, key string, noExpiry bool, to string) error {
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

package service

import (
	"errors"
	"fmt"
	"slices"

	"golang.org/x/text/unicode/norm"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
)

// Sentinels matched (errors.Is) by a Sign or bulk-row error when the
// inserted YubiKey's key could not sign a credential the verify page
// accepts. Sign's SignError.Message and a bulk row's error carry the
// specific text (the key's end date, its allowed honors).
var (
	// errKeyNotRegistered: no registry entry has the card's key.
	errKeyNotRegistered = errors.New("This YubiKey's key is not in the registry, so the credential would not verify. Use a registered YubiKey.")
	// errKeyExpired: the card's key is registered, but only until before the
	// credential date.
	errKeyExpired = errors.New("This YubiKey's key is not valid on the credential date, so the credential would not verify.")
	// errHonorNotAllowed: the card's key is registered for the date, but its
	// allowed_honors excludes the credential's honor.
	errHonorNotAllowed = errors.New("This YubiKey's key may not sign this honor, so the credential would not verify.")
)

// keyRejectedError is a key check failure: msg is the user-facing text and
// reason one of errKeyNotRegistered, errKeyExpired, errHonorNotAllowed.
type keyRejectedError struct {
	msg    string
	reason error
}

func (e *keyRejectedError) Error() string { return e.msg }
func (e *keyRejectedError) Unwrap() error { return e.reason }

// keyChecker returns nil when the card key pub may sign req, else a
// *keyRejectedError.
type keyChecker func(pub [32]byte, req core.SignRequest) error

// checkSigningKey is the keyChecker for reg. It mirrors the verify page's
// per-key check (src/verify.ts, step 5): an entry accepts when its key
// decodes equal to pub, core.IsDateInRange(req.Date, entry), and its
// allowed_honors is unrestricted or holds the NFC honor exactly. Any
// accepting entry wins; else a date failure is reported before an honor
// failure, and the first such entry (registry order) supplies the message's
// date or honor list. The verify page rejects a whole registry holding an
// invalid allowed_honors; here only that entry accepts nothing, and the
// registry's validity is left to CI's committed-registry test. req.Date is
// already validated, so a date failure always has an end date.
func checkSigningKey(reg core.Registry, pub [32]byte, req core.SignRequest) error {
	honor := norm.NFC.String(req.Honor)
	var dateFail, honorFail *core.KeyEntry
	for i := range reg.Keys {
		entry := &reg.Keys[i]
		key, err := core.DecodePublicKey(*entry)
		if err != nil || key != pub {
			continue
		}
		switch {
		case !core.IsDateInRange(req.Date, *entry):
			if dateFail == nil {
				dateFail = entry
			}
		case honorAllowed(*entry, honor):
			return nil
		case honorFail == nil:
			honorFail = entry
		}
	}
	switch {
	case dateFail != nil && dateFail.To == nil: // a malformed req.Date
		return &keyRejectedError{msg: errKeyExpired.Error(), reason: errKeyExpired}
	case dateFail != nil:
		return &keyRejectedError{
			msg: fmt.Sprintf("This YubiKey's key is valid only until %s, before the credential date %s, so the credential would not verify.",
				core.FormatDateDisplay(*dateFail.To), core.FormatDateDisplay(req.Date)),
			reason: errKeyExpired,
		}
	case honorFail != nil:
		return &keyRejectedError{
			msg: fmt.Sprintf("This YubiKey's key may not sign “%s” credentials (allowed: %s), so the credential would not verify.",
				honor, restrictionsText(*honorFail)),
			reason: errHonorNotAllowed,
		}
	default:
		return &keyRejectedError{msg: errKeyNotRegistered.Error(), reason: errKeyNotRegistered}
	}
}

// honorAllowed reports whether entry's allowed_honors lets it sign honor.
func honorAllowed(entry core.KeyEntry, honor string) bool {
	honors, valid := allowedHonors(entry)
	return valid && (len(honors) == 0 || slices.Contains(honors, honor))
}

// errNoPINForKeyRead is what the card gets if it asks for a PIN while it is
// opened only to read its public key, which needs none: an unexpected prompt
// fails instead of sending an empty PIN that could use up a retry.
var errNoPINForKeyRead = errors.New("no PIN is available while reading the card key")

// noPIN is the PIN reader for a card opened only to read its public key.
func noPIN() (string, error) { return "", errNoPINForKeyRead }

// readCardKey opens the card without a PIN, reads its public key and closes
// it, so the key can be checked before the PIN prompt. Errors are classified
// as signAndLog's: an open failure is returned as-is, an export failure
// wrapped in a *signFlowError with phaseExportKey.
func readCardKey(openAdapter adapterOpener, logger *debuglog.Logger) ([32]byte, error) {
	adapter, closer, err := openAdapter(noPIN)
	if err != nil {
		logger.Log("connect: " + core.SanitizeForLog(err.Error()))
		return [32]byte{}, err
	}
	defer closer.Close()
	pub, err := adapter.ExportPublicKey()
	if err != nil {
		logger.Log(sanitizeError("ExportPublicKey", err))
		return [32]byte{}, &signFlowError{Phase: phaseExportKey, Err: err}
	}
	return pub, nil
}

// logKeyRejected logs a key check failure by its fixed reason text only; the
// message holds the operator's honor and date.
func logKeyRejected(logger *debuglog.Logger, prefix string, err error) {
	var kr *keyRejectedError
	if errors.As(err, &kr) {
		logger.Log(prefix + kr.reason.Error())
	}
}

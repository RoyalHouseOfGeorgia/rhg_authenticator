package rpc

import (
	"context"

	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
)

// method adapts f, which takes params decoded into P, to a handler.
func method[P any](f func(s *server, p P) (any, error)) handler {
	return func(s *server, params []byte) (any, error) {
		var p P
		if err := decodeParams(params, &p); err != nil {
			return nil, err
		}
		return f(s, p)
	}
}

// noParams adapts f, which takes no params, to a handler; params must still
// be empty or an object without fields.
func noParams(f func(s *server) (any, error)) handler {
	return method(func(s *server, _ struct{}) (any, error) { return f(s) })
}

// void returns the result of a method with no result value.
func void(err error) (any, error) {
	if err != nil {
		return nil, err
	}
	return struct{}{}, nil
}

// orEmpty returns s, or an empty slice if s is nil, so it encodes as [].
func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// Params objects.
type (
	pathParams struct {
		Path string `json:"path"`
	}
	saveQRParams struct {
		URL    string `json:"url"`
		Format string `json:"format"`
		Path   string `json:"path"`
	}
	reportParams struct {
		ReportID string `json:"reportId"`
	}
	addEntryParams struct {
		Form      service.EntryForm `json:"form"`
		PublicKey string            `json:"publicKey"`
	}
	updateEntryParams struct {
		Index     int               `json:"index"`
		PublicKey string            `json:"publicKey"`
		Form      service.EntryForm `json:"form"`
	}
	queryParams struct {
		Query string `json:"query"`
	}
	recordParams struct {
		Record *service.HistoryRecord `json:"record"` // required
	}
	revokeParams struct {
		PayloadSHA256 string `json:"payloadSha256"`
	}
)

// Result objects for methods whose service call returns a bare value.
type (
	honorsResult struct {
		Honors []string `json:"honors"`
	}
	columnsResult struct {
		Columns []string `json:"columns"`
	}
	publicKeyResult struct {
		PublicKey string `json:"publicKey"`
	}
	recordTextResult struct {
		Detail        string `json:"detail"`
		RevokeConfirm string `json:"revokeConfirm"`
		DeleteConfirm string `json:"deleteConfirm"`
		OfferRevoke   bool   `json:"offerRevoke"` // offer revoking instead of deleting
	}
	deleteEntryResult struct {
		Backup  string `json:"backup"`
		Title   string `json:"title"`
		Message string `json:"message"`
	}
	duplicatePreviewResult struct {
		Count          int    `json:"count"`
		ConfirmMessage string `json:"confirmMessage"`
	}
	removeDuplicatesResult struct {
		Removed int    `json:"removed"`
		Backup  string `json:"backup"`
		Message string `json:"message"`
	}
)

// methodTable returns the method handlers by name. Calls get
// context.Background(): only bulk.run, auth.login and a waiting PIN prompt
// can be cancelled (bulk.cancel, auth.cancelLogin, pin.cancel, and
// app.shutdown for all three); every other call runs to completion or its
// own timeout.
func methodTable() map[string]handler {
	bg := context.Background()
	return map[string]handler{
		"app.init":           method((*server).initApp),
		"app.start":          noParams((*server).start),
		"app.canQuit":        noParams((*server).canQuit),
		"app.shutdown":       method((*server).shutdown),
		"app.info":           noParams(func(s *server) (any, error) { return s.app.Info(), nil }),
		"app.exportErrorLog": method((*server).exportErrorLog),

		"sign.honors": noParams(func(s *server) (any, error) {
			return honorsResult{Honors: orEmpty(s.app.Honors())}, nil
		}),
		"sign.validate": method(func(_ *server, p service.SignFields) (any, error) { return void(p.Validate()) }),
		"sign.sign":     method(func(s *server, p service.SignFields) (any, error) { return s.app.Sign(bg, p) }),
		"sign.saveQR": method(func(s *server, p saveQRParams) (any, error) {
			return void(s.app.SaveQR(p.URL, p.Format, p.Path))
		}),
		"sign.reportError": method(func(s *server, p reportParams) (any, error) {
			return s.app.ReportSignError(bg, p.ReportID)
		}),

		"bulk.load": method(func(s *server, p pathParams) (any, error) {
			plan, err := s.app.LoadBulk(p.Path)
			if err != nil {
				return nil, err
			}
			plan.PreviewNames, plan.InvalidLines = orEmpty(plan.PreviewNames), orEmpty(plan.InvalidLines)
			return plan, nil
		}),
		"bulk.run": noParams(func(s *server) (any, error) {
			out, err := s.app.RunBulk(bg)
			out.FailedLines = orEmpty(out.FailedLines)
			return out, err
		}),
		"bulk.cancel": noParams(func(s *server) (any, error) { s.app.CancelBulk(); return void(nil) }),
		"bulk.exportResults": method(func(s *server, p pathParams) (any, error) {
			return void(s.app.ExportBulkResults(p.Path))
		}),

		"yubikey.check": noParams(func(s *server) (any, error) {
			kc, err := s.app.CheckYubiKey()
			if err != nil {
				return nil, err
			}
			kc.Details = orEmpty(kc.Details)
			return kc, nil
		}),

		"auth.state":       noParams(func(s *server) (any, error) { return s.app.AuthState(), nil }),
		"auth.login":       noParams(func(s *server) (any, error) { return s.app.Login(bg) }),
		"auth.cancelLogin": noParams(func(s *server) (any, error) { s.app.CancelLogin(); return void(nil) }),
		"auth.logout":      noParams(func(s *server) (any, error) { s.app.Logout(); return void(nil) }),

		"registry.snapshot": noParams(func(s *server) (any, error) {
			snap := s.app.Registry()
			snap.Entries, snap.Rows = orEmpty(snap.Entries), orEmpty(snap.Rows)
			return snap, nil
		}),
		"registry.columns": noParams(func(*server) (any, error) {
			return columnsResult{Columns: orEmpty(service.RegistryColumns())}, nil
		}),
		"registry.fetch": noParams(func(s *server) (any, error) { return void(s.app.FetchRegistry(bg)) }),
		"registry.addEntry": method(func(s *server, p addEntryParams) (any, error) {
			return void(s.app.AddEntry(p.Form, p.PublicKey))
		}),
		"registry.updateEntry": method(func(s *server, p updateEntryParams) (any, error) {
			return void(s.app.UpdateEntry(p.Index, p.PublicKey, p.Form))
		}),
		"registry.importCertificate": method(func(s *server, p pathParams) (any, error) {
			key, err := s.app.ImportCertificate(p.Path)
			if err != nil {
				return nil, err
			}
			return publicKeyResult{PublicKey: key}, nil
		}),
		"registry.importFromYubiKey": noParams(func(s *server) (any, error) {
			key, err := s.app.ImportFromYubiKey()
			if err != nil {
				return nil, err
			}
			return publicKeyResult{PublicKey: key}, nil
		}),
		"registry.submit": noParams(func(s *server) (any, error) { return s.app.SubmitRegistry(bg) }),

		"history.refresh": noParams(func(s *server) (any, error) { s.app.RefreshHistory(); return void(nil) }),
		"history.list": method(func(s *server, p queryParams) (any, error) {
			snap := s.app.History(p.Query)
			snap.Rows = orEmpty(snap.Rows)
			return snap, nil
		}),
		"history.recordText": method(func(s *server, p recordParams) (any, error) {
			if p.Record == nil {
				return nil, errBadParams
			}
			rec := *p.Record
			deleteConfirm, offerRevoke := s.app.DeleteConfirm(rec)
			return recordTextResult{
				Detail:        service.FormatRecordDetail(rec),
				RevokeConfirm: service.RevokeConfirmText(rec),
				DeleteConfirm: deleteConfirm,
				OfferRevoke:   offerRevoke,
			}, nil
		}),
		"history.deleteEntry": method(func(s *server, p recordParams) (any, error) {
			if p.Record == nil {
				return nil, errBadParams
			}
			backup, err := s.app.DeleteEntry(*p.Record)
			if err != nil {
				return nil, err
			}
			title, message := service.RecordDeletedText(*p.Record, backup)
			return deleteEntryResult{Backup: backup, Title: title, Message: message}, nil
		}),
		"history.revoke": method(func(s *server, p revokeParams) (any, error) {
			return s.app.Revoke(bg, p.PayloadSHA256)
		}),
		"history.exportIssuanceLog": method(func(s *server, p pathParams) (any, error) {
			if err := s.app.ExportIssuanceLog(p.Path); err != nil {
				return nil, err
			}
			return service.IssuanceLogExported(p.Path), nil
		}),
		"history.duplicatePreview": noParams(func(s *server) (any, error) {
			n, err := s.app.DuplicatePreview()
			if err != nil {
				return nil, err
			}
			return duplicatePreviewResult{Count: n, ConfirmMessage: service.DuplicatesConfirmText(n)}, nil
		}),
		"history.removeDuplicates": noParams(func(s *server) (any, error) {
			removed, backup, err := s.app.RemoveDuplicates()
			if err != nil {
				return nil, err
			}
			return removeDuplicatesResult{
				Removed: removed,
				Backup:  backup,
				Message: service.DuplicatesRemovedText(removed, backup),
			}, nil
		}),

		"pin.submit": method(func(s *server, p pinSubmitParams) (any, error) {
			return void(s.pins.answer(p.RequestID, pinAnswer{pin: p.PIN, remember: p.Remember}))
		}),
		"pin.cancel": method(func(s *server, p pinCancelParams) (any, error) {
			return void(s.pins.answer(p.RequestID, pinAnswer{}))
		}),

		"update.current": noParams((*server).updateCurrent),

		"audit.commits": noParams(func(s *server) (any, error) {
			res, err := s.app.AuditCommits()
			if err != nil {
				return nil, err
			}
			res.Rows = orEmpty(res.Rows)
			return res, nil
		}),
	}
}

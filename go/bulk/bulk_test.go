package bulk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

var testHonors = []string{"Order of the Crown of Georgia", "Other"}

// keyAdapter signs with an in-memory Ed25519 key.
type keyAdapter struct{ key ed25519.PrivateKey }

func (a keyAdapter) ExportPublicKey() ([32]byte, error) {
	var pub [32]byte
	copy(pub[:], a.key.Public().(ed25519.PublicKey))
	return pub, nil
}

func (a keyAdapter) SignBytes(data []byte) ([]byte, error) {
	return ed25519.Sign(a.key, data), nil
}

func testKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
}

// realSign returns a signFn backed by core.HandleSign and an in-test key.
func realSign(t *testing.T) func(core.SignRequest) (core.SignResponse, error) {
	t.Helper()
	a := keyAdapter{testKey()}
	pub, _ := a.ExportPublicKey()
	return func(req core.SignRequest) (core.SignResponse, error) {
		return core.HandleSign(req, a, pub)
	}
}

func row(line int, name, honor, detail, date string) Row {
	return Row{Line: line, Name: name, Honor: honor, Detail: detail, Date: date}
}

func mustPayload(t *testing.T, req core.SignRequest) []byte {
	t.Helper()
	p, err := core.BuildPayload(req)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPlanClassification(t *testing.T) {
	crown := testHonors[0]
	tests := []struct {
		name      string
		row       Row
		wantState string
		wantErr   string
	}{
		{"valid", row(2, "Davit", crown, "For service", "2026-03-15"), StatusToSign, ""},
		{"padded cells", row(2, "  Davit ", "\tOther ", " d ", " 2026-03-15 "), StatusToSign, ""},
		{"honor case near-miss", row(2, "Davit", "order of the crown of georgia", "d", "2026-03-15"), StatusInvalid, `honor: not one of the allowed honor titles: "` + strings.Join(testHonors, `", "`) + `"`},
		{"US date", row(2, "Davit", crown, "d", "3/15/2026"), StatusInvalid, "invalid credential data: invalid date: 3/15/2026"},
		{"impossible date", row(2, "Davit", crown, "d", "2026-02-30"), StatusInvalid, "invalid date"},
		{"control char in detail", row(2, "Davit", crown, "a\x07b", "2026-03-15"), StatusInvalid, "detail contains invalid control characters"},
		{"empty name", row(2, "  ", crown, "d", "2026-03-15"), StatusInvalid, "recipient must not be empty"},
		{"over-length recipient", row(2, strings.Repeat("ბ", 501), crown, "d", "2026-03-15"), StatusInvalid, "recipient exceeds maximum length of 500"},
		{"parse error", Row{Line: 2, Name: "A", ParseErr: "missing value for detail"}, StatusInvalid, "missing value for detail"},
		{"mis-encoded Georgian name", row(2, "????? ??????", crown, "d", "2026-03-15"), StatusInvalid, "looks mis-encoded"},
		{"replacement char in detail", row(2, "Davit", crown, "a\uFFFDb", "2026-03-15"), StatusInvalid, "looks mis-encoded"},
		{"single question mark allowed", row(2, "Davit", crown, "Why not?", "2026-03-15"), StatusToSign, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := Plan([]Row{tc.row}, testHonors, nil)[0]
			if res.Status != tc.wantState {
				t.Fatalf("status = %q (err %q), want %q", res.Status, res.Err, tc.wantState)
			}
			if !strings.Contains(res.Err, tc.wantErr) || (tc.wantErr == "" && res.Err != "") {
				t.Fatalf("err = %q, want containing %q", res.Err, tc.wantErr)
			}
			wantReq := core.SignRequest{
				Recipient: strings.TrimSpace(tc.row.Name),
				Honor:     strings.TrimSpace(tc.row.Honor),
				Detail:    strings.TrimSpace(tc.row.Detail),
				Date:      strings.TrimSpace(tc.row.Date),
			}
			if res.Req != wantReq {
				t.Fatalf("Req = %+v, want %+v", res.Req, wantReq)
			}
			if res.Row != tc.row {
				t.Fatalf("Row not preserved: %+v", res.Row)
			}
			if tc.wantState == StatusToSign {
				if want := core.PayloadSHA256Hex(mustPayload(t, wantReq)); res.Hash != want {
					t.Fatalf("Hash = %q, want %q", res.Hash, want)
				}
			} else if res.Hash != "" {
				t.Fatalf("invalid row has Hash %q", res.Hash)
			}
			if res.URL != "" {
				t.Fatalf("unexpected URL %q", res.URL)
			}
		})
	}
}

func TestPlanAlreadyIssued(t *testing.T) {
	req := core.SignRequest{Recipient: "ბაგრატიონი", Honor: "Other", Detail: "d", Date: "2026-03-15"}
	payload := mustPayload(t, req)
	hash := core.PayloadSHA256Hex(payload)
	sig := core.Encode(ed25519.Sign(testKey(), payload))
	issued := map[string]string{hash: sig}

	rows := []Row{row(2, req.Recipient, req.Honor, req.Detail, req.Date), row(3, " "+req.Recipient, req.Honor, req.Detail, req.Date)}
	res := Plan(rows, testHonors, issued)
	wantURL := core.BuildVerifyURL(core.Encode(payload), sig)
	if r := res[0]; r.Status != StatusAlreadyIssued || r.URL != wantURL || r.Hash != hash || r.Err != "" {
		t.Errorf("result 0 = %+v, want already_issued with URL %q", r, wantURL)
	}
	// A second copy of the same credential in the file is a duplicate, even when
	// the first copy was already issued.
	if r := res[1]; r.Status != StatusInvalid || r.URL != "" || r.Err != "duplicate of line 2 (same credential)" {
		t.Errorf("result 1 = %+v, want invalid duplicate of line 2", r)
	}
}

func TestPlanInFileDuplicateAndOrder(t *testing.T) {
	rows := []Row{
		row(2, "A", "Other", "d", "2026-01-01"),
		{Line: 3, Name: "X", ParseErr: "missing value for honor"},
		row(4, "B", "Other", "d", "2026-01-01"),
		row(7, " A ", "Other", "d", "2026-01-01"),
		row(8, "A", "Other", "d", "2026-01-01"),
	}
	res := Plan(rows, testHonors, map[string]string{})
	want := []struct{ status, err string }{
		{StatusToSign, ""},
		{StatusInvalid, "missing value for honor"},
		{StatusToSign, ""},
		{StatusInvalid, "duplicate of line 2 (same credential)"},
		{StatusInvalid, "duplicate of line 2 (same credential)"},
	}
	for i, w := range want {
		if res[i].Line != rows[i].Line || res[i].Status != w.status || res[i].Err != w.err {
			t.Errorf("result %d = line %d %q %q, want %q %q", i, res[i].Line, res[i].Status, res[i].Err, w.status, w.err)
		}
	}
}

// mixedPlan returns: invalid, to_sign x3, already_issued (fixed order).
func mixedPlan(t *testing.T) []Result {
	t.Helper()
	issuedReq := core.SignRequest{Recipient: "Old", Honor: "Other", Detail: "d", Date: "2025-01-01"}
	p := mustPayload(t, issuedReq)
	issued := map[string]string{core.PayloadSHA256Hex(p): core.Encode(ed25519.Sign(testKey(), p))}
	rows := []Row{
		{Line: 2, Name: "Bad", ParseErr: "missing value for honor"},
		row(3, "R1", "Other", "d", "2026-01-01"),
		row(4, "R2", "Other", "d", "2026-01-01"),
		row(5, "R3", "Other", "d", "2026-01-01"),
		row(6, "Old", "Other", "d", "2025-01-01"),
	}
	res := Plan(rows, testHonors, issued)
	if c := Summarize(res); c.ToSign != 3 || c.Invalid != 1 || c.AlreadyIssued != 1 {
		t.Fatalf("fixture counts = %+v", c)
	}
	return res
}

type progressCall struct {
	done, total int
	name        string
}

func recordProgress(calls *[]progressCall) func(int, int, string) {
	return func(done, total int, name string) {
		*calls = append(*calls, progressCall{done, total, name})
	}
}

func describeErr(err error) string { return "described: " + err.Error() }

func TestRunAllSucceed(t *testing.T) {
	res := mixedPlan(t)
	before := []Result{res[0], res[4]}
	var calls []progressCall
	if err := Run(context.Background(), res, realSign(t), describeErr, recordProgress(&calls)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := []progressCall{{0, 3, "R1"}, {1, 3, "R2"}, {2, 3, "R3"}}
	if fmt.Sprint(calls) != fmt.Sprint(want) {
		t.Fatalf("progress = %v, want %v", calls, want)
	}
	for _, r := range res[1:4] {
		payload := mustPayload(t, r.Req)
		if r.Status != StatusSigned || r.Err != "" || !strings.HasPrefix(r.URL, core.VerifyBaseURL+"?p="+core.Encode(payload)+"&s=") {
			t.Errorf("result = %+v", r)
		}
	}
	if res[0] != before[0] || res[4] != before[1] {
		t.Fatalf("non-to_sign rows modified")
	}
}

func TestRunCancel(t *testing.T) {
	for _, k := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("cancel during row %d", k), func(t *testing.T) {
			res := mixedPlan(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sign := realSign(t)
			n := 0
			var calls []progressCall
			err := Run(ctx, res, func(req core.SignRequest) (core.SignResponse, error) {
				n++
				if n == k {
					cancel()
				}
				return sign(req)
			}, describeErr, recordProgress(&calls))

			if len(calls) != k {
				t.Fatalf("progress calls = %d, want %d", len(calls), k)
			}
			toSign := res[1:4]
			for i := range toSign {
				want := StatusSigned
				if i >= k {
					want = StatusNotAttempted
				}
				if toSign[i].Status != want {
					t.Errorf("row %d status = %q, want %q", i+1, toSign[i].Status, want)
				}
				if (want == StatusSigned) != (toSign[i].URL != "") {
					t.Errorf("row %d URL = %q", i+1, toSign[i].URL)
				}
			}
			if k == 3 {
				if err != nil {
					t.Fatalf("cancel during last row: err = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("err = %v, want context.Canceled", err)
			}
		})
	}
}

func TestRunCancelledBeforeStart(t *testing.T) {
	res := mixedPlan(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := Run(ctx, res, func(core.SignRequest) (core.SignResponse, error) {
		t.Fatal("signFn called")
		return core.SignResponse{}, nil
	}, describeErr, func(int, int, string) { t.Fatal("onProgress called") })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if c := Summarize(res); c.NotAttempted != 3 || c.ToSign != 0 {
		t.Fatalf("counts = %+v", c)
	}
}

var errHardware = errors.New("hardware exploded")

func TestRunGenericError(t *testing.T) {
	res := mixedPlan(t)
	sign := realSign(t)
	n := 0
	var calls []progressCall
	err := Run(context.Background(), res, func(req core.SignRequest) (core.SignResponse, error) {
		n++
		if n == 2 {
			return core.SignResponse{URL: "should-not-be-used"}, errHardware
		}
		return sign(req)
	}, describeErr, recordProgress(&calls))

	if err != errHardware || !errors.Is(err, errHardware) {
		t.Fatalf("err = %v, want original errHardware unwrapped", err)
	}
	if len(calls) != 2 {
		t.Fatalf("progress calls = %v", calls)
	}
	if res[1].Status != StatusSigned || res[1].URL == "" {
		t.Errorf("row 1 = %+v", res[1])
	}
	if res[2].Status != StatusFailed || res[2].Err != "described: hardware exploded" || res[2].URL != "" {
		t.Errorf("row 2 = %+v", res[2])
	}
	if res[3].Status != StatusNotAttempted || res[3].URL != "" {
		t.Errorf("row 3 = %+v", res[3])
	}
	if res[0].Status != StatusInvalid || res[4].Status != StatusAlreadyIssued {
		t.Errorf("non-to_sign rows modified")
	}
}

func TestRunNotLogged(t *testing.T) {
	res := mixedPlan(t)
	sign := realSign(t)
	notLogged := fmt.Errorf("%w: disk full", core.ErrNotLogged)
	err := Run(context.Background(), res, func(req core.SignRequest) (core.SignResponse, error) {
		resp, _ := sign(req)
		return resp, notLogged
	}, func(error) string { t.Fatal("describe called"); return "" }, func(int, int, string) {})

	if err != notLogged {
		t.Fatalf("err = %v, want original", err)
	}
	if res[1].Status != StatusSigned || res[1].URL == "" || res[1].Err != "signed but NOT recorded in audit log" {
		t.Errorf("row 1 = %+v", res[1])
	}
	for _, r := range res[2:4] {
		if r.Status != StatusNotAttempted {
			t.Errorf("row = %+v", r)
		}
	}
}

func TestMarkNotAttempted(t *testing.T) {
	res := mixedPlan(t)
	MarkNotAttempted(res)
	c := Summarize(res)
	if c.ToSign != 0 || c.NotAttempted != 3 || c.Invalid != 1 || c.AlreadyIssued != 1 {
		t.Fatalf("counts = %+v", c)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestWriteResultCSV(t *testing.T) {
	res := []Result{
		{Req: core.SignRequest{Recipient: "ბაგრატიონი", Honor: "Other", Detail: "a, \"b\"\nc", Date: "2026-01-01"}, URL: "https://x/?p=1&s=2", Status: StatusSigned},
		{Req: core.SignRequest{Recipient: "Bad"}, Status: StatusInvalid, Err: "missing value for honor"},
	}
	var buf bytes.Buffer
	if err := WriteResultCSV(&buf, res); err != nil {
		t.Fatal(err)
	}
	out := buf.Bytes()
	if !bytes.HasPrefix(out, []byte{0xEF, 0xBB, 0xBF}) {
		t.Fatalf("missing BOM")
	}
	recs, err := csv.NewReader(bytes.NewReader(out[3:])).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"name", "honor", "detail", "date", "url", "status", "error"},
		{"ბაგრატიონი", "Other", "a, \"b\"\nc", "2026-01-01", "https://x/?p=1&s=2", "signed", ""},
		{"Bad", "", "", "", "", "invalid", "missing value for honor"},
	}
	if fmt.Sprintf("%q", recs) != fmt.Sprintf("%q", want) {
		t.Fatalf("records = %q, want %q", recs, want)
	}
}

func TestWriteResultCSVWriterError(t *testing.T) {
	if err := WriteResultCSV(failWriter{}, nil); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("err = %v", err)
	}
}

func TestSummarizeEndToEnd(t *testing.T) {
	in := hdr +
		"A,Other,d,2026-01-01\n" +
		"B,Other\n" + // short → invalid
		"A,Other,d,2026-01-01\n" + // dup → invalid
		",,,\n" + // blank → not counted
		"C,Other,d,2026-01-01\n" +
		"D,Other,d,2026-01-01\n" +
		"E,Other,d,2026-01-01\n" +
		"Old,Other,d,2025-01-01\n"
	rows, err := ParseCSV([]byte(in), MaxRows)
	if err != nil {
		t.Fatal(err)
	}
	p := mustPayload(t, core.SignRequest{Recipient: "Old", Honor: "Other", Detail: "d", Date: "2025-01-01"})
	res := Plan(rows, testHonors, map[string]string{core.PayloadSHA256Hex(p): "sig"})
	if c := Summarize(res); c.ToSign != 4 {
		t.Fatalf("pre-run counts = %+v", c)
	}
	sign := realSign(t)
	n := 0
	runErr := Run(context.Background(), res, func(req core.SignRequest) (core.SignResponse, error) {
		n++
		if n == 3 {
			return core.SignResponse{}, errHardware
		}
		return sign(req)
	}, describeErr, func(int, int, string) {})
	if runErr != errHardware {
		t.Fatalf("err = %v", runErr)
	}
	c := Summarize(res)
	want := Counts{Total: 7, Signed: 2, AlreadyIssued: 1, Invalid: 2, Failed: 1, NotAttempted: 1}
	if c != want {
		t.Fatalf("counts = %+v, want %+v", c, want)
	}
	if c.Signed+c.AlreadyIssued+c.Invalid+c.Failed+c.NotAttempted != c.Total {
		t.Fatalf("invariant broken: %+v", c)
	}
	if c.Successful() != 3 {
		t.Fatalf("Successful = %d", c.Successful())
	}
}

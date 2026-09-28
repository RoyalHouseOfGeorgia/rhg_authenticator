package bulk

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

const hdr = "name,honor,detail,date\n"

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("disk on fire") }

func TestReadInput(t *testing.T) {
	pattern := []byte("a,b,c,d\n")
	exact := bytes.Repeat(pattern, MaxBytes/len(pattern))
	if len(exact) != MaxBytes {
		t.Fatalf("fixture size = %d, want %d", len(exact), MaxBytes)
	}
	tests := []struct {
		name    string
		in      []byte
		want    []byte
		wantErr string
	}{
		{"exactly MaxBytes", exact, exact, ""},
		{"MaxBytes+1", append(bytes.Clone(exact), 'x'), nil, "file larger than 2 MB"},
		{"empty", []byte{}, nil, "file is empty"},
		{"BOM only", []byte{0xEF, 0xBB, 0xBF}, nil, "file is empty"},
		{"cp1252", []byte("name\nCaf\xe9\n"), nil, "file is not UTF-8"},
		{"BOM stripped", []byte("\xef\xbb\xbfname\n"), []byte("name\n"), ""},
		{"no BOM", []byte("ბაგრატიონი"), []byte("ბაგრატიონი"), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ReadInput(bytes.NewReader(tc.in))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				if got != nil {
					t.Fatalf("got data on error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestReadInputReaderError(t *testing.T) {
	if _, err := ReadInput(errReader{}); err == nil || !strings.Contains(err.Error(), "disk on fire") {
		t.Fatalf("err = %v", err)
	}
}

func TestReadInputBOMBeforeQuotedHeader(t *testing.T) {
	data, err := ReadInput(strings.NewReader("\xef\xbb\xbf\"name\",\"honor\",\"detail\",\"date\"\nA,Other,d,2026-01-01\n"))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := ParseCSV(data, MaxRows)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Name != "A" {
		t.Fatalf("rows = %+v", rows)
	}
}

func TestParseCSVHeaderVariants(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"canonical", hdr + "A,Other,d,2026-01-01\n"},
		{"reordered", "date,detail,honor,name\n2026-01-01,d,Other,A\n"},
		{"case and whitespace", " Name ,HONOR,\tDetail, date\nA,Other,d,2026-01-01\n"},
		{"extra unknown column", "notes,name,honor,detail,date\nhello,A,Other,d,2026-01-01\n"},
		{"trailing empty header cells", "name,honor,detail,date,,\nA,Other,d,2026-01-01,,\n"},
		{"CRLF", "name,honor,detail,date\r\nA,Other,d,2026-01-01\r\n"},
	}
	want := Row{Line: 2, Name: "A", Honor: "Other", Detail: "d", Date: "2026-01-01"}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := ParseCSV([]byte(tc.in), MaxRows)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if len(rows) != 1 || rows[0] != want {
				t.Fatalf("rows = %+v, want [%+v]", rows, want)
			}
		})
	}
}

func TestParseCSVFileErrors(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		max     int
		wantErr string
	}{
		{"empty data", "", MaxRows, "file is empty"},
		{"missing header", "name,honor,date\nA,Other,2026-01-01\n", MaxRows, `missing required column "detail"`},
		{"semicolon delimiter", "name;honor;detail;date\nA;Other;d;2026-01-01\n", MaxRows, "file uses ';' as delimiter — re-save with commas"},
		{"duplicate required header", "name,honor,detail,date,Name\nA,Other,d,2026-01-01,B\n", MaxRows, `column "name" more than once`},
		{"malformed header", "\"name,honor,detail,date\n", MaxRows, "malformed CSV"},
		{"malformed data quotes", hdr + "A \"x\",Other,d,2026-01-01\n", MaxRows, "line 2"},
		{"zero data rows", hdr, MaxRows, "file has no data rows"},
		{"only blank data rows", hdr + ",,,\n  , ,\t,\n", MaxRows, "file has no data rows"},
		{"over row cap", hdr + "A,O,d,x\nB,O,d,x\nC,O,d,x\nD,O,d,x\n", 3, "more than 3 data rows"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := ParseCSV([]byte(tc.in), tc.max)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
			if strings.Contains(tc.wantErr, "malformed") && !strings.HasPrefix(err.Error(), "malformed CSV") {
				t.Fatalf("err = %v, want malformed CSV prefix", err)
			}
			if rows != nil {
				t.Fatalf("rows returned on error: %+v", rows)
			}
		})
	}
}

func TestParseCSVRowCapIgnoresBlankRows(t *testing.T) {
	in := hdr + ",,,\nA,O,d,x\n,,,\nB,O,d,x\n\n , , , \nC,O,d,x\n,,,\n"
	rows, err := ParseCSV([]byte(in), 3)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("len = %d, want 3", len(rows))
	}
	wantLines := []int{3, 5, 8}
	for i, r := range rows {
		if r.Line != wantLines[i] {
			t.Errorf("row %d Line = %d, want %d", i, r.Line, wantLines[i])
		}
	}
}

func TestParseCSVRowLevelProblems(t *testing.T) {
	in := hdr +
		"A,Other\n" + // short
		"B,Other,d,2026-01-01,oops\n" + // overflow non-empty
		"C,Other,d,2026-01-01,, \n" + // overflow empty
		"ბაგრატიონი,Other,დეტალი,2026-01-01\n"
	rows, err := ParseCSV([]byte(in), MaxRows)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	want := []Row{
		{Line: 2, Name: "A", Honor: "Other", ParseErr: "missing value for detail"},
		{Line: 3, Name: "B", Honor: "Other", Detail: "d", Date: "2026-01-01", ParseErr: "more cells than header columns (unquoted comma?)"},
		{Line: 4, Name: "C", Honor: "Other", Detail: "d", Date: "2026-01-01"},
		{Line: 5, Name: "ბაგრატიონი", Honor: "Other", Detail: "დეტალი", Date: "2026-01-01"},
	}
	if len(rows) != len(want) {
		t.Fatalf("rows = %+v", rows)
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("row %d = %+v, want %+v", i, rows[i], want[i])
		}
	}
}

func TestParseCSVShortRowFirstColumnMissing(t *testing.T) {
	rows, err := ParseCSV([]byte("detail,date,honor,name\nd\n"), MaxRows)
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].ParseErr != "missing value for name" || rows[0].Detail != "d" {
		t.Fatalf("row = %+v", rows[0])
	}
}

func TestParseCSVMultilineCellLineNumbers(t *testing.T) {
	in := hdr + "\"A\nB\",Other,\"line1\nline2\",2026-01-01\nC,Other,d,2026-01-02\n"
	rows, err := ParseCSV([]byte(in), MaxRows)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %+v", rows)
	}
	if rows[0].Line != 2 || rows[0].Name != "A\nB" {
		t.Errorf("row 0 = %+v", rows[0])
	}
	if rows[1].Line != 5 {
		t.Errorf("row 1 Line = %d, want 5", rows[1].Line)
	}
}

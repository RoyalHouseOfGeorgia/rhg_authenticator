// Package bulk implements CSV-driven bulk credential signing: reading and
// parsing the operator's input file, planning which rows to sign, running the
// signing loop, and exporting the results.
package bulk

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode/utf8"
)

// MaxBytes is the maximum accepted input file size.
const MaxBytes = 2 << 20

// MaxRows is the maximum number of non-blank data rows accepted per file.
const MaxRows = 500

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// requiredColumns lists the required header names in canonical order.
var requiredColumns = []string{"name", "honor", "detail", "date"}

// Row is one non-blank data record from the input CSV, holding raw cell text.
// ParseErr is set when the record is structurally unusable.
type Row struct {
	Line     int
	Name     string
	Honor    string
	Detail   string
	Date     string
	ParseErr string
}

// ReadInput reads at most MaxBytes from r, rejects oversized, empty, and
// non-UTF-8 input, and returns the content with any leading UTF-8 BOM removed.
func ReadInput(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}
	if len(data) > MaxBytes {
		return nil, errors.New("file larger than 2 MB")
	}
	data = bytes.TrimPrefix(data, utf8BOM)
	if len(data) == 0 {
		return nil, errors.New("file is empty")
	}
	if !utf8.Valid(data) {
		return nil, errors.New("file is not UTF-8 — in Excel use Save As → CSV UTF-8")
	}
	return data, nil
}

// ParseCSV parses data as a comma-separated file whose first record is a
// header containing the columns name, honor, detail, and date (any order,
// case-insensitive; unknown columns ignored). Blank records are skipped.
// Structural problems in individual records are reported via Row.ParseErr;
// file-level problems return an error.
func ParseCSV(data []byte, maxRows int) ([]Row, error) {
	cr := csv.NewReader(bytes.NewReader(data))
	cr.LazyQuotes = false
	cr.FieldsPerRecord = -1

	header, err := cr.Read()
	if errors.Is(err, io.EOF) {
		return nil, errors.New("file is empty")
	}
	if err != nil {
		return nil, malformed(err)
	}

	idx, err := headerIndex(header)
	if err != nil {
		return nil, err
	}

	var rows []Row
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, malformed(err)
		}
		if isBlank(rec) {
			continue
		}
		if len(rows) == maxRows {
			return nil, fmt.Errorf("file has more than %d data rows", maxRows)
		}
		line, _ := cr.FieldPos(0)
		rows = append(rows, buildRow(rec, line, idx, len(header)))
	}
	if len(rows) == 0 {
		return nil, errors.New("file has no data rows")
	}
	return rows, nil
}

// headerIndex maps each required column to its index in header.
func headerIndex(header []string) (map[string]int, error) {
	idx := make(map[string]int, len(requiredColumns))
	for i, h := range header {
		key := strings.ToLower(strings.TrimSpace(h))
		if !slices.Contains(requiredColumns, key) {
			continue
		}
		if _, dup := idx[key]; dup {
			return nil, fmt.Errorf("header has column %q more than once", key)
		}
		idx[key] = i
	}
	for _, col := range requiredColumns {
		if _, ok := idx[col]; ok {
			continue
		}
		if len(header) == 1 && strings.Contains(header[0], ";") {
			return nil, errors.New("file uses ';' as delimiter — re-save with commas")
		}
		return nil, fmt.Errorf("missing required column %q (need name, honor, detail, date)", col)
	}
	return idx, nil
}

func buildRow(rec []string, line int, idx map[string]int, width int) Row {
	row := Row{
		Line:   line,
		Name:   cellAt(rec, idx["name"]),
		Honor:  cellAt(rec, idx["honor"]),
		Detail: cellAt(rec, idx["detail"]),
		Date:   cellAt(rec, idx["date"]),
	}
	for _, col := range requiredColumns {
		if idx[col] >= len(rec) {
			row.ParseErr = "missing value for " + col
			return row
		}
	}
	for _, cell := range rec[min(width, len(rec)):] {
		if strings.TrimSpace(cell) != "" {
			row.ParseErr = "more cells than header columns (unquoted comma?)"
			return row
		}
	}
	return row
}

// cellAt returns rec[i], or "" when rec is too short.
func cellAt(rec []string, i int) string {
	if i < len(rec) {
		return rec[i]
	}
	return ""
}

func isBlank(rec []string) bool {
	for _, cell := range rec {
		if strings.TrimSpace(cell) != "" {
			return false
		}
	}
	return true
}

func malformed(err error) error {
	return fmt.Errorf("malformed CSV: %w", err)
}

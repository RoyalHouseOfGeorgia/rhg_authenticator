package core

import (
	"strings"
	"testing"
)

// validObj returns a valid v1 credential map for testing.
func validObj() map[string]any {
	return map[string]any{
		"authority": "Royal House of Georgia",
		"date":      "2025-03-12",
		"detail":    "Awarded for distinguished service",
		"honor":     "Order of the Golden Fleece",
		"recipient": "John Doe",
		"version":   float64(1),
	}
}

func TestValidateCredential_Valid(t *testing.T) {
	cred, err := ValidateCredential(validObj())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.Authority != "Royal House of Georgia" {
		t.Errorf("authority = %q, want %q", cred.Authority, "Royal House of Georgia")
	}
	if cred.Date != "2025-03-12" {
		t.Errorf("date = %q, want %q", cred.Date, "2025-03-12")
	}
	if cred.Detail != "Awarded for distinguished service" {
		t.Errorf("detail = %q", cred.Detail)
	}
	if cred.Honor != "Order of the Golden Fleece" {
		t.Errorf("honor = %q", cred.Honor)
	}
	if cred.Recipient != "John Doe" {
		t.Errorf("recipient = %q", cred.Recipient)
	}
	if cred.Version != 1 {
		t.Errorf("version = %d, want 1", cred.Version)
	}
}

func TestValidateCredential_NilInput(t *testing.T) {
	_, err := ValidateCredential(nil)
	if err == nil || err.Error() != "credential must be a plain object" {
		t.Fatalf("expected 'credential must be a plain object', got %v", err)
	}
}

func TestValidateCredential_MissingVersion(t *testing.T) {
	obj := validObj()
	delete(obj, "version")
	_, err := ValidateCredential(obj)
	if err == nil || err.Error() != "missing required field: version" {
		t.Fatalf("expected 'missing required field: version', got %v", err)
	}
}

func TestValidateCredential_VersionAsString(t *testing.T) {
	obj := validObj()
	obj["version"] = "1"
	_, err := ValidateCredential(obj)
	if err == nil || err.Error() != "version must be a number" {
		t.Fatalf("expected 'version must be a number', got %v", err)
	}
}

func TestValidateCredential_Version2(t *testing.T) {
	obj := validObj()
	obj["version"] = float64(2)
	_, err := ValidateCredential(obj)
	if err == nil || !strings.Contains(err.Error(), "Unsupported credential version") {
		t.Fatalf("expected unsupported version error, got %v", err)
	}
}

func TestValidateCredential_MissingFields(t *testing.T) {
	for _, field := range stringFields {
		obj := validObj()
		delete(obj, field)
		_, err := ValidateCredential(obj)
		expected := "missing required field: " + field
		if err == nil || err.Error() != expected {
			t.Errorf("field %s: expected %q, got %v", field, expected, err)
		}
	}
}

func TestValidateCredential_WrongTypes(t *testing.T) {
	for _, field := range stringFields {
		obj := validObj()
		obj[field] = float64(42)
		_, err := ValidateCredential(obj)
		expected := field + " must be a string"
		if err == nil || err.Error() != expected {
			t.Errorf("field %s: expected %q, got %v", field, expected, err)
		}
	}
}

func TestValidateCredential_LeadingWhitespace(t *testing.T) {
	obj := validObj()
	obj["authority"] = " Royal House"
	_, err := ValidateCredential(obj)
	if err == nil || err.Error() != "authority must not have leading or trailing whitespace" {
		t.Fatalf("expected whitespace error, got %v", err)
	}
}

func TestValidateCredential_TrailingWhitespace(t *testing.T) {
	obj := validObj()
	obj["recipient"] = "John Doe "
	_, err := ValidateCredential(obj)
	if err == nil || err.Error() != "recipient must not have leading or trailing whitespace" {
		t.Fatalf("expected whitespace error, got %v", err)
	}
}

func TestValidateCredential_ControlChars_NullByte(t *testing.T) {
	obj := validObj()
	obj["honor"] = "Order\x00Fleece"
	_, err := ValidateCredential(obj)
	if err == nil || err.Error() != "honor contains invalid control characters" {
		t.Fatalf("expected control char error, got %v", err)
	}
}

func TestValidateCredential_ControlChars_Tab(t *testing.T) {
	obj := validObj()
	obj["detail"] = "Some\tdetail"
	_, err := ValidateCredential(obj)
	if err == nil || err.Error() != "detail contains invalid control characters" {
		t.Fatalf("expected control char error, got %v", err)
	}
}

func TestValidateCredential_ControlChars_Bidi(t *testing.T) {
	obj := validObj()
	obj["authority"] = "Authority\u202aOverride"
	_, err := ValidateCredential(obj)
	if err == nil || err.Error() != "authority contains invalid control characters" {
		t.Fatalf("expected control char error, got %v", err)
	}
}

func TestValidateCredential_EmptyFields(t *testing.T) {
	// The whitespace check comes before the empty check, so a whitespace-only
	// string would fail on whitespace. An empty string is valid for TrimSpace
	// but fails on the empty check.
	for _, field := range stringFields {
		obj := validObj()
		obj[field] = ""
		_, err := ValidateCredential(obj)
		expected := field + " must not be empty"
		if err == nil || err.Error() != expected {
			t.Errorf("field %s: expected %q, got %v", field, expected, err)
		}
	}
}

func TestValidateCredential_MaxLengthBoundary(t *testing.T) {
	// Exactly at max — should pass.
	obj := validObj()
	obj["authority"] = strings.Repeat("A", 200)
	_, err := ValidateCredential(obj)
	if err != nil {
		t.Fatalf("expected no error at max length, got %v", err)
	}
}

func TestValidateCredential_MaxLengthExceeded(t *testing.T) {
	obj := validObj()
	obj["authority"] = strings.Repeat("A", 201)
	_, err := ValidateCredential(obj)
	if err == nil || err.Error() != "authority exceeds maximum length of 200" {
		t.Fatalf("expected max length error, got %v", err)
	}
}

func TestValidateCredential_MaxLengthGeorgianText(t *testing.T) {
	// Georgian characters are multi-byte but each is 1 rune.
	// 200 Georgian characters should pass for authority (max 200 runes).
	obj := validObj()
	obj["authority"] = strings.Repeat("ა", 200) // Georgian letter "a"
	_, err := ValidateCredential(obj)
	if err != nil {
		t.Fatalf("expected no error with 200 Georgian runes, got %v", err)
	}

	// 201 Georgian characters should fail.
	obj["authority"] = strings.Repeat("ა", 201)
	_, err = ValidateCredential(obj)
	if err == nil || err.Error() != "authority exceeds maximum length of 200" {
		t.Fatalf("expected max length error for 201 Georgian runes, got %v", err)
	}
}

func TestValidateCredential_ExtraKeys(t *testing.T) {
	obj := validObj()
	obj["extra"] = "value"
	_, err := ValidateCredential(obj)
	if err == nil || err.Error() != "unexpected field: extra" {
		t.Fatalf("expected unexpected field error, got %v", err)
	}
}

func TestValidateCredential_InvalidDate(t *testing.T) {
	obj := validObj()
	obj["date"] = "2025-02-30"
	_, err := ValidateCredential(obj)
	if err == nil || err.Error() != "invalid date: 2025-02-30" {
		t.Fatalf("expected invalid date error, got %v", err)
	}
}

func TestValidateCredential_Year0000(t *testing.T) {
	obj := validObj()
	obj["date"] = "0000-01-01"
	_, err := ValidateCredential(obj)
	if err == nil || err.Error() != "invalid date: 0000-01-01" {
		t.Fatalf("expected invalid date error for year 0000, got %v", err)
	}
}

func TestValidateCredential_DateMaxLength(t *testing.T) {
	obj := validObj()
	obj["date"] = strings.Repeat("2", 11) // 11 chars exceeds max 10
	_, err := ValidateCredential(obj)
	if err == nil || err.Error() != "date exceeds maximum length of 10" {
		t.Fatalf("expected max length error for date, got %v", err)
	}
}

func TestSanitizeForError(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{"he\x00llo", "hello"},
		{"test\u202aoverride\u202e", "testoverride"},
		{string([]rune{0x01, 0x1f, 0x7f, 0x9f}), ""},
		{"normal text", "normal text"},
	}
	for _, tt := range tests {
		got := SanitizeForError(tt.input)
		if got != tt.want {
			t.Errorf("SanitizeForError(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestValidateCredential_ValidationOrder(t *testing.T) {
	// Verify that version is checked before string fields.
	obj := map[string]any{
		"version": "not a number",
	}
	_, err := ValidateCredential(obj)
	if err == nil || err.Error() != "version must be a number" {
		t.Fatalf("expected version type error first, got %v", err)
	}

	// Verify that missing field comes before wrong type.
	obj = map[string]any{
		"version": float64(1),
	}
	_, err = ValidateCredential(obj)
	if err == nil || err.Error() != "missing required field: authority" {
		t.Fatalf("expected missing authority first, got %v", err)
	}
}

func TestValidateCredential_FieldValidationOrder(t *testing.T) {
	// Fields should be validated in order: authority, date, detail, honor, recipient.
	// If authority is valid but date is missing, we should get date error.
	obj := map[string]any{
		"version":   float64(1),
		"authority": "Valid Authority",
	}
	_, err := ValidateCredential(obj)
	if err == nil || err.Error() != "missing required field: date" {
		t.Fatalf("expected missing date, got %v", err)
	}
}

func TestValidateCredential_VersionNonInteger(t *testing.T) {
	obj := validObj()
	obj["version"] = float64(1.5)
	_, err := ValidateCredential(obj)
	if err == nil || !strings.Contains(err.Error(), "Unsupported credential version") {
		t.Fatalf("expected unsupported version error for 1.5, got %v", err)
	}
}

func TestValidateCredential_DateWithControlChars(t *testing.T) {
	obj := validObj()
	obj["date"] = "2025\x00-01"
	_, err := ValidateCredential(obj)
	if err == nil || err.Error() != "date contains invalid control characters" {
		t.Fatalf("expected control char error for date, got %v", err)
	}
}

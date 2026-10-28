package core

import (
	"strings"
	"testing"
)

// validObj returns a valid v1 credential map for testing.
func validObj() map[string]any {
	return map[string]any{
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

func TestValidateCredential_Whitespace(t *testing.T) {
	tests := []struct {
		name      string
		recipient string
	}{
		{"LeadingWhitespace", " John Doe"},
		{"TrailingWhitespace", "John Doe "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := validObj()
			obj["recipient"] = tt.recipient
			_, err := ValidateCredential(obj)
			if err == nil || err.Error() != "recipient must not have leading or trailing whitespace" {
				t.Fatalf("expected whitespace error, got %v", err)
			}
		})
	}
}

// TestValidateCredential_SurroundingBOM checks that a leading or trailing
// U+FEFF is rejected like whitespace, matching JS trim() on the verify page.
func TestValidateCredential_SurroundingBOM(t *testing.T) {
	for _, field := range stringFields {
		for _, pos := range []string{"leading", "trailing"} {
			t.Run(field+"/"+pos, func(t *testing.T) {
				obj := validObj()
				v := obj[field].(string)
				if pos == "leading" {
					obj[field] = "\ufeff" + v
				} else {
					obj[field] = v + "\ufeff"
				}
				_, err := ValidateCredential(obj)
				want := field + " must not have leading or trailing whitespace"
				if err == nil || err.Error() != want {
					t.Fatalf("expected %q, got %v", want, err)
				}
			})
		}
	}
}

func TestValidateCredential_ControlChars(t *testing.T) {
	tests := []struct {
		name  string
		field string
		value string
	}{
		{"ControlChars_NullByte", "honor", "Order\x00Fleece"},
		{"ControlChars_Tab", "detail", "Some\tdetail"},
		{"ControlChars_Bidi", "honor", "Honor\u202aOverride"},
		{"DateWithControlChars", "date", "2025\x00-01"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := validObj()
			obj[tt.field] = tt.value
			_, err := ValidateCredential(obj)
			want := tt.field + " contains invalid control characters"
			if err == nil || err.Error() != want {
				t.Fatalf("expected %q, got %v", want, err)
			}
		})
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

func TestValidateCredential_MaxLengthGeorgianText(t *testing.T) {
	// Georgian characters are multi-byte but each is 1 rune.
	// 200 Georgian characters should pass for honor (max 200 runes).
	obj := validObj()
	obj["honor"] = strings.Repeat("ა", 200) // Georgian letter "a"
	_, err := ValidateCredential(obj)
	if err != nil {
		t.Fatalf("expected no error with 200 Georgian runes, got %v", err)
	}

	// 201 Georgian characters should fail.
	obj["honor"] = strings.Repeat("ა", 201)
	_, err = ValidateCredential(obj)
	if err == nil || err.Error() != "honor exceeds maximum length of 200" {
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

func TestValidateCredential_Version(t *testing.T) {
	withVersion := func(v any) map[string]any {
		obj := validObj()
		obj["version"] = v
		return obj
	}
	withoutVersion := validObj()
	delete(withoutVersion, "version")
	tests := []struct {
		name         string
		obj          map[string]any
		wantExact    string
		wantContains string
	}{
		{name: "MissingVersion", obj: withoutVersion, wantExact: "missing required field: version"},
		{name: "VersionAsString", obj: withVersion("1"), wantExact: "version must be a number"},
		{name: "Version2", obj: withVersion(float64(2)), wantContains: "unsupported credential version"},
		{name: "VersionNonInteger", obj: withVersion(float64(1.5)), wantContains: "unsupported credential version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateCredential(tt.obj)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if tt.wantExact != "" && err.Error() != tt.wantExact {
				t.Fatalf("expected %q, got %v", tt.wantExact, err)
			}
			if tt.wantContains != "" && !strings.Contains(err.Error(), tt.wantContains) {
				t.Fatalf("expected error containing %q, got %v", tt.wantContains, err)
			}
		})
	}
}

func TestValidateCredential_FieldOrder(t *testing.T) {
	tests := []struct {
		name string
		obj  map[string]any
		want string
	}{
		// Version is checked before string fields.
		{"ValidationOrder version first", map[string]any{"version": "not a number"}, "version must be a number"},
		// The first missing string field is reported (stringFields order: date, detail, honor, recipient).
		{"ValidationOrder first missing field", map[string]any{"version": float64(1)}, "missing required field: date"},
		{"FieldValidationOrder", map[string]any{"version": float64(1), "date": "2025-03-12"}, "missing required field: detail"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateCredential(tt.obj)
			if err == nil || err.Error() != tt.want {
				t.Fatalf("expected %q, got %v", tt.want, err)
			}
		})
	}
}

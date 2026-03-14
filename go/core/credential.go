package core

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// CredentialV1 represents a validated v1 credential.
type CredentialV1 struct {
	Authority string `json:"authority"`
	Date      string `json:"date"`
	Detail    string `json:"detail"`
	Honor     string `json:"honor"`
	Recipient string `json:"recipient"`
	Version   int    `json:"version"`
}

// controlCharPattern matches C0/C1 control characters and bidi overrides.
const controlCharPattern = `[\x00-\x1f\x7f-\x9f\x{061c}\x{200e}\x{200f}\x{202a}-\x{202e}\x{2066}-\x{2069}]`

var controlCharRE = regexp.MustCompile(controlCharPattern)

// SanitizeForError strips all control characters and bidi overrides from s.
func SanitizeForError(s string) string {
	return controlCharRE.ReplaceAllString(s, "")
}

// stringFields defines the required string fields in validation order.
var stringFields = []string{"authority", "date", "detail", "honor", "recipient"}

// allFields is the complete set of allowed fields.
var allFields = map[string]bool{
	"authority": true,
	"date":      true,
	"detail":    true,
	"honor":     true,
	"recipient": true,
	"version":   true,
}

// fieldMaxLengths defines the maximum rune count for each string field.
var fieldMaxLengths = map[string]int{
	"authority": 200,
	"date":      10,
	"detail":    2000,
	"honor":     200,
	"recipient": 500,
}

// ValidateCredential validates a parsed JSON object as a v1 credential.
// Input is map[string]any (from json.Unmarshal into an interface{}).
// Returns the validated credential or an error.
func ValidateCredential(obj map[string]any) (CredentialV1, error) {
	if obj == nil {
		return CredentialV1{}, fmt.Errorf("credential must be a plain object")
	}

	// 1. Version check.
	verRaw, ok := obj["version"]
	if !ok {
		return CredentialV1{}, fmt.Errorf("missing required field: version")
	}
	verNum, ok := verRaw.(float64)
	if !ok {
		return CredentialV1{}, fmt.Errorf("version must be a number")
	}
	if verNum != 1 {
		return CredentialV1{}, fmt.Errorf("Unsupported credential version: %v", verNum)
	}

	// 2. String fields — validated in order.
	values := make(map[string]string, len(stringFields))
	for _, field := range stringFields {
		raw, exists := obj[field]
		if !exists {
			return CredentialV1{}, fmt.Errorf("missing required field: %s", field)
		}
		s, ok := raw.(string)
		if !ok {
			return CredentialV1{}, fmt.Errorf("%s must be a string", field)
		}
		if s != strings.TrimSpace(s) {
			return CredentialV1{}, fmt.Errorf("%s must not have leading or trailing whitespace", field)
		}
		if controlCharRE.MatchString(s) {
			return CredentialV1{}, fmt.Errorf("%s contains invalid control characters", field)
		}
		if s == "" {
			return CredentialV1{}, fmt.Errorf("%s must not be empty", field)
		}
		if utf8.RuneCountInString(s) > fieldMaxLengths[field] {
			return CredentialV1{}, fmt.Errorf("%s exceeds maximum length of %d", field, fieldMaxLengths[field])
		}
		values[field] = s
	}

	// 3. Extra keys.
	for key := range obj {
		if !allFields[key] {
			return CredentialV1{}, fmt.Errorf("unexpected field: %s", key)
		}
	}

	// 4. Date validation.
	if !IsValidDate(values["date"]) {
		return CredentialV1{}, fmt.Errorf("invalid date: %s", SanitizeForError(values["date"]))
	}

	return CredentialV1{
		Authority: values["authority"],
		Date:      values["date"],
		Detail:    values["detail"],
		Honor:     values["honor"],
		Recipient: values["recipient"],
		Version:   1,
	}, nil
}

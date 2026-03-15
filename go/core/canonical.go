package core

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// maxDepth is the maximum allowed nesting depth for canonicalized objects.
const maxDepth = 4

// Canonicalize produces deterministic UTF-8 JSON bytes from a map.
// Keys are sorted lexicographically at all levels. String values are
// NFC-normalized. It rejects __proto__ keys, non-finite numbers,
// negative zero, and unsupported value types.
func Canonicalize(obj map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeValue(&buf, obj, 0); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// writeValue writes the JSON representation of v into buf.
// depth tracks nesting for objects and arrays.
func writeValue(buf *bytes.Buffer, v any, depth int) error {
	switch val := v.(type) {
	case nil:
		buf.WriteString("null")

	case bool:
		if val {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}

	case float64:
		if math.IsNaN(val) || math.IsInf(val, 0) {
			return fmt.Errorf("non-finite number is not valid JSON: %v", val)
		}
		if val == 0 && math.Signbit(val) {
			return errors.New("negative zero is not a valid JSON value")
		}
		s, err := formatNumber(val)
		if err != nil {
			return err
		}
		buf.WriteString(s)

	case int:
		buf.WriteString(strconv.Itoa(val))

	case string:
		if err := writeJSONString(buf, norm.NFC.String(val)); err != nil {
			return err
		}

	case []any:
		if depth >= maxDepth {
			return errors.New("value exceeds maximum nesting depth")
		}
		buf.WriteByte('[')
		for i, elem := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeValue(buf, elem, depth+1); err != nil {
				return err
			}
		}
		buf.WriteByte(']')

	case map[string]any:
		if depth >= maxDepth {
			return errors.New("object exceeds maximum nesting depth")
		}
		keys := make([]string, 0, len(val))
		for k := range val {
			if k == "__proto__" {
				return errors.New(`"__proto__" is not allowed as a JSON key`)
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)

		buf.WriteByte('{')
		first := true
		for _, k := range keys {
			if first {
				first = false
			} else {
				buf.WriteByte(',')
			}
			// Keys are NOT NFC-normalized per spec.
			if err := writeJSONString(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeValue(buf, val[k], depth+1); err != nil {
				return err
			}
		}
		buf.WriteByte('}')

	default:
		return fmt.Errorf("unsupported value type: %T", v)
	}

	return nil
}

// formatNumber formats a float64 as an integer string.
// It rejects non-integer values and values outside the safe integer range.
func formatNumber(v float64) (string, error) {
	if v != math.Trunc(v) {
		return "", fmt.Errorf("non-integer float values are not supported in canonical JSON")
	}
	const maxSafeInt = 1<<53 - 1
	if v > maxSafeInt || v < -maxSafeInt {
		return "", fmt.Errorf("integer value %v exceeds safe range", v)
	}
	return strconv.FormatInt(int64(v), 10), nil
}

// writeJSONString writes a JSON-escaped string to buf, matching the
// escaping rules of JavaScript's JSON.stringify (RFC 8259 §7).
func writeJSONString(buf *bytes.Buffer, s string) error {
	buf.WriteByte('"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			return fmt.Errorf("invalid UTF-8 byte at position %d", i)
		}
		switch {
		case r == '"':
			buf.WriteString(`\"`)
		case r == '\\':
			buf.WriteString(`\\`)
		case r == '\b':
			buf.WriteString(`\b`)
		case r == '\f':
			buf.WriteString(`\f`)
		case r == '\n':
			buf.WriteString(`\n`)
		case r == '\r':
			buf.WriteString(`\r`)
		case r == '\t':
			buf.WriteString(`\t`)
		case r < 0x20:
			// Other control characters: \uXXXX with lowercase hex.
			fmt.Fprintf(buf, `\u%04x`, r)
		default:
			buf.WriteString(s[i : i+size])
		}
		i += size
	}
	buf.WriteByte('"')
	return nil
}

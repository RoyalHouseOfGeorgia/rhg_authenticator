package core

import (
	"bytes"
	"strings"
	"testing"
)

func TestEncodeEmpty(t *testing.T) {
	got := Encode(nil)
	if got != "" {
		t.Errorf("Encode(nil) = %q, want empty string", got)
	}
	got = Encode([]byte{})
	if got != "" {
		t.Errorf("Encode([]byte{}) = %q, want empty string", got)
	}
}

func TestEncodeKnownVectors(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{"hello", []byte("hello"), "aGVsbG8"},
		{"single byte", []byte{0xff}, "_w"},
		{"url-unsafe chars", []byte{0xfb, 0xff, 0xfe}, "-__-"},
		{"padding would be needed", []byte{0x00}, "AA"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Encode(tt.input)
			if got != tt.want {
				t.Errorf("Encode(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRoundTrip(t *testing.T) {
	inputs := [][]byte{
		nil,
		{},
		{0x00},
		{0xff},
		[]byte("hello world"),
		{0x01, 0x02, 0x03, 0x04, 0x05},
	}

	for _, input := range inputs {
		encoded := Encode(input)
		decoded, err := Decode(encoded)
		if err != nil {
			t.Fatalf("Decode(Encode(%v)) error: %v", input, err)
		}
		// nil and empty both decode to empty
		if len(input) == 0 && len(decoded) == 0 {
			continue
		}
		if !bytes.Equal(decoded, input) {
			t.Errorf("round-trip failed for %v: got %v", input, decoded)
		}
	}
}

func TestDecodeRemainder1Rejected(t *testing.T) {
	// A single character is remainder 1 (invalid Base64).
	_, err := Decode("A")
	if err == nil {
		t.Error("Decode(\"A\") should return error for remainder-1 input")
	}

	// 5 chars is also remainder 1.
	_, err = Decode("AAAAA")
	if err == nil {
		t.Error("Decode(\"AAAAA\") should return error for remainder-1 input")
	}
}

func TestDecodePaddedInput(t *testing.T) {
	// "aGVsbG8=" is "hello" with padding
	got, err := Decode("aGVsbG8=")
	if err != nil {
		t.Fatalf("Decode padded input error: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("Decode padded = %q, want %q", string(got), "hello")
	}
}

func TestDecodeUnpaddedInput(t *testing.T) {
	got, err := Decode("aGVsbG8")
	if err != nil {
		t.Fatalf("Decode unpadded error: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("Decode unpadded = %q, want %q", string(got), "hello")
	}
}

func TestDecodeInvalidChars(t *testing.T) {
	_, err := Decode("!!!!")
	if err == nil {
		t.Error("Decode with invalid chars should return error")
	}
}

func TestDecodeStandard(t *testing.T) {
	// Standard base64 for "hello"
	got, err := DecodeStandard("aGVsbG8=")
	if err != nil {
		t.Fatalf("DecodeStandard error: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("DecodeStandard = %q, want %q", string(got), "hello")
	}
}

func TestDecodeStandardMaxLength(t *testing.T) {
	// 256 chars should be accepted.
	input256 := strings.Repeat("AAAA", 64) // 256 chars
	_, err := DecodeStandard(input256)
	if err != nil {
		t.Fatalf("DecodeStandard with 256 chars should succeed: %v", err)
	}

	// 257 chars should be rejected.
	input257 := strings.Repeat("AAAA", 64) + "A"
	_, err = DecodeStandard(input257)
	if err == nil {
		t.Error("DecodeStandard with 257 chars should return error")
	}
}

func TestDecodeStandardInvalid(t *testing.T) {
	_, err := DecodeStandard("not valid base64!!!")
	if err == nil {
		t.Error("DecodeStandard with invalid input should return error")
	}
}

func TestDecodeStandardEmpty(t *testing.T) {
	got, err := DecodeStandard("")
	if err != nil {
		t.Fatalf("DecodeStandard empty error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("DecodeStandard empty = %v, want empty", got)
	}
}

package regmgr

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"os"
	"testing"
)

func TestExtractEd25519Key_ValidPEM(t *testing.T) {
	certData, err := os.ReadFile("../testdata/test-ed25519.crt")
	if err != nil {
		t.Fatalf("failed to read test fixture: %v", err)
	}

	key, err := ExtractEd25519Key(certData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(key) != 44 {
		t.Errorf("expected 44-char base64 string, got %d chars", len(key))
	}
}

func TestExtractEd25519Key_RSACert(t *testing.T) {
	certData, err := os.ReadFile("../testdata/test-rsa.crt")
	if err != nil {
		t.Fatalf("failed to read test fixture: %v", err)
	}

	_, err = ExtractEd25519Key(certData)
	if err == nil {
		t.Fatal("expected error for RSA cert, got nil")
	}
	if got := err.Error(); got != "certificate does not contain an Ed25519 public key" {
		t.Errorf("unexpected error message: %s", got)
	}
}

func TestExtractEd25519Key_RandomBytes(t *testing.T) {
	garbage := make([]byte, 256)
	if _, err := rand.Read(garbage); err != nil {
		t.Fatalf("failed to generate random bytes: %v", err)
	}

	_, err := ExtractEd25519Key(garbage)
	if err == nil {
		t.Fatal("expected error for random bytes, got nil")
	}
	if got := err.Error(); len(got) < 25 || got[:25] != "not a valid certificate: " {
		t.Errorf("expected error starting with 'not a valid certificate: ', got: %s", got)
	}
}

func TestExtractEd25519Key_CorruptedPEM(t *testing.T) {
	corrupted := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("this is not a valid DER certificate"),
	})

	_, err := ExtractEd25519Key(corrupted)
	if err == nil {
		t.Fatal("expected error for corrupted PEM, got nil")
	}
	if got := err.Error(); len(got) < 25 || got[:25] != "not a valid certificate: " {
		t.Errorf("expected error starting with 'not a valid certificate: ', got: %s", got)
	}
}

func TestExtractEd25519Key_EmptyInput(t *testing.T) {
	_, err := ExtractEd25519Key([]byte{})
	if err == nil {
		t.Fatal("expected error for empty input, got nil")
	}
	if got := err.Error(); len(got) < 25 || got[:25] != "not a valid certificate: " {
		t.Errorf("expected error starting with 'not a valid certificate: ', got: %s", got)
	}
}

func TestExtractEd25519Key_ValidDER(t *testing.T) {
	certPEM, err := os.ReadFile("../testdata/test-ed25519.crt")
	if err != nil {
		t.Fatalf("failed to read test fixture: %v", err)
	}

	// Decode PEM to get raw DER bytes.
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode PEM block from test fixture")
	}

	key, err := ExtractEd25519Key(block.Bytes)
	if err != nil {
		t.Fatalf("unexpected error with DER input: %v", err)
	}
	if len(key) != 44 {
		t.Errorf("expected 44-char base64 string, got %d chars", len(key))
	}

	// Verify DER and PEM paths produce identical keys.
	keyFromPEM, _ := ExtractEd25519Key(certPEM)
	if key != keyFromPEM {
		t.Errorf("DER and PEM paths returned different keys: %s vs %s", key, keyFromPEM)
	}
}

func TestExtractEd25519Key_RawKeyLength(t *testing.T) {
	certData, err := os.ReadFile("../testdata/test-ed25519.crt")
	if err != nil {
		t.Fatalf("failed to read test fixture: %v", err)
	}

	key, err := ExtractEd25519Key(certData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}
	if len(raw) != 32 {
		t.Errorf("expected 32-byte raw key, got %d bytes", len(raw))
	}
}

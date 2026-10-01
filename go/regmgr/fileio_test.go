package regmgr

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

func validRegistry() core.Registry {
	return core.Registry{
		Keys: []core.KeyEntry{{
			Authority: "Test Authority",
			From:      "2025-01-01",
			To:        nil,
			Algorithm: "Ed25519",
			PublicKey: "/PjT+j342wWZypb0m/4MSBsFhHrrqzpoTe2rZ9hf0XU=",
			Note:      "Test key",
		}},
	}
}

// --- MarshalRegistry tests ---

func TestMarshalRegistry_ValidOutput(t *testing.T) {
	reg := validRegistry()

	data, err := MarshalRegistry(reg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Must end with a newline.
	if !bytes.HasSuffix(data, []byte("\n")) {
		t.Error("output does not end with trailing newline")
	}

	// Must contain 2-space indentation (json.MarshalIndent with "  ").
	if !bytes.Contains(data, []byte("  ")) {
		t.Error("output does not contain 2-space indent")
	}

	// Must be valid JSON that can round-trip through ValidateRegistry.
	if _, err := core.ValidateRegistry(data); err != nil {
		t.Errorf("output is not valid registry JSON: %v", err)
	}
}

func TestMarshalRegistry_RoundTrip(t *testing.T) {
	reg := validRegistry()

	data, err := MarshalRegistry(reg)
	if err != nil {
		t.Fatalf("MarshalRegistry: %v", err)
	}

	got, err := core.ValidateRegistry(data)
	if err != nil {
		t.Fatalf("ValidateRegistry: %v", err)
	}

	if len(got.Keys) != len(reg.Keys) {
		t.Fatalf("key count = %d, want %d", len(got.Keys), len(reg.Keys))
	}
	if got.Keys[0].Authority != reg.Keys[0].Authority {
		t.Errorf("authority = %q, want %q", got.Keys[0].Authority, reg.Keys[0].Authority)
	}
	if got.Keys[0].PublicKey != reg.Keys[0].PublicKey {
		t.Errorf("public_key = %q, want %q", got.Keys[0].PublicKey, reg.Keys[0].PublicKey)
	}
	if got.Extra != nil || got.Keys[0].Extra != nil {
		t.Errorf("Extra should be nil without unknown fields, got %v / %v", got.Extra, got.Keys[0].Extra)
	}

	t.Run("preserves unknown fields", func(t *testing.T) {
		reg := validRegistry()
		reg.Extra = map[string]json.RawMessage{"version": json.RawMessage(`2`)}
		reg.Keys[0].Extra = map[string]json.RawMessage{
			"allowed_honors": json.RawMessage(`["Order A","Order B"]`),
			`quo"te`:         json.RawMessage(`{"a":1}`),
		}

		data, err := MarshalRegistry(reg)
		if err != nil {
			t.Fatalf("MarshalRegistry: %v", err)
		}
		got, err := core.ValidateRegistry(data)
		if err != nil {
			t.Fatalf("ValidateRegistry: %v", err)
		}

		if v := string(got.Extra["version"]); v != "2" {
			t.Errorf("registry Extra[version] = %q, want %q", v, "2")
		}
		if len(got.Extra) != 1 {
			t.Errorf("len(registry Extra) = %d, want 1", len(got.Extra))
		}
		entryExtra := got.Keys[0].Extra
		if len(entryExtra) != 2 {
			t.Fatalf("len(entry Extra) = %d, want 2: %v", len(entryExtra), entryExtra)
		}
		var honors []string
		if err := json.Unmarshal(entryExtra["allowed_honors"], &honors); err != nil {
			t.Fatalf("unmarshal allowed_honors: %v", err)
		}
		if len(honors) != 2 || honors[0] != "Order A" || honors[1] != "Order B" {
			t.Errorf("allowed_honors = %v", honors)
		}
		var quoted map[string]int
		if err := json.Unmarshal(entryExtra[`quo"te`], &quoted); err != nil {
			t.Fatalf("unmarshal quo\"te: %v", err)
		}
		if quoted["a"] != 1 {
			t.Errorf(`Extra[quo"te] = %v`, quoted)
		}

		again, err := MarshalRegistry(got)
		if err != nil {
			t.Fatalf("second MarshalRegistry: %v", err)
		}
		if !bytes.Equal(again, data) {
			t.Errorf("round-trip not idempotent:\nfirst:\n%s\nsecond:\n%s", data, again)
		}
	})
}

func TestMarshalRegistry_EmptyKeys(t *testing.T) {
	reg := core.Registry{Keys: []core.KeyEntry{}}

	_, err := MarshalRegistry(reg)
	if err == nil {
		t.Fatal("expected error for empty keys")
	}
	if !strings.Contains(err.Error(), "validation failed") {
		t.Errorf("error = %v, want containing %q", err, "validation failed")
	}
}

func TestMarshalRegistry_Deterministic(t *testing.T) {
	reg := validRegistry()

	data1, err := MarshalRegistry(reg)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}

	data2, err := MarshalRegistry(reg)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}

	if !bytes.Equal(data1, data2) {
		t.Error("two calls with same input produced different output")
	}
}

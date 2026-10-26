package core

import (
	"math"
	"testing"
)

func TestCanonicalizeSimpleObject(t *testing.T) {
	obj := map[string]any{
		"version": float64(1),
		"type":    "credential",
		"subject": "test",
	}
	got, err := Canonicalize(obj)
	if err != nil {
		t.Fatalf("Canonicalize error: %v", err)
	}
	want := `{"subject":"test","type":"credential","version":1}`
	if string(got) != want {
		t.Errorf("got %q, want %q", string(got), want)
	}
}

func TestCanonicalizeNFCNormalization(t *testing.T) {
	// e + combining acute accent (U+0065 U+0301) → é (U+00E9)
	obj := map[string]any{
		"name": "e\u0301",
	}
	got, err := Canonicalize(obj)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	// Expected: {"name":"é"} where é is U+00E9 (NFC form)
	want := []byte{123, 34, 110, 97, 109, 101, 34, 58, 34, 195, 169, 34, 125}
	if string(got) != string(want) {
		t.Errorf("NFC normalization failed:\n  got  %v\n  want %v", got, want)
	}
}

func TestCanonicalizeRejects(t *testing.T) {
	tests := []struct {
		name string
		obj  map[string]any
	}{
		{"ProtoRejection", map[string]any{"__proto__": "bad"}},
		{"NestedProtoRejection", map[string]any{"a": map[string]any{"__proto__": "bad"}}},
		{"NegativeZero", map[string]any{"val": math.Copysign(0, -1)}},
		{"NaN", map[string]any{"val": math.NaN()}},
		{"Infinity +Inf", map[string]any{"val": math.Inf(1)}},
		{"Infinity -Inf", map[string]any{"val": math.Inf(-1)}},
		{"InvalidUTF8Value", map[string]any{"val": "hello\xffworld"}},
		{"InvalidUTF8Key", map[string]any{"bad\xffkey": "value"}},
		// An unsupported type inside an array should propagate the error.
		{"ErrorInArray", map[string]any{"arr": []any{"ok", complex(1, 2)}}},
		{"FormatNumberErrors large exponent", map[string]any{"val": 1e20}},
		{"FormatNumberErrors small negative exponent", map[string]any{"val": 1e-7}},
		{"FormatNumberErrors half", map[string]any{"val": 0.5}},
		{"FormatNumberErrors max float64", map[string]any{"val": math.MaxFloat64}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Canonicalize(tt.obj); err == nil {
				t.Errorf("expected error for %v", tt.obj)
			}
		})
	}
}

func TestCanonicalizeDepthLimit(t *testing.T) {
	// Depth counting: top-level map is depth 0, each nested map increments.
	// maxDepth=4 means depth >= 4 is rejected.
	// 5 nested maps: depth 0 -> 1 -> 2 -> 3 -> 4 (rejected)
	obj := map[string]any{
		"a": map[string]any{
			"b": map[string]any{
				"c": map[string]any{
					"d": map[string]any{
						"e": "too deep",
					},
				},
			},
		},
	}
	_, err := Canonicalize(obj)
	if err == nil {
		t.Error("expected depth limit error")
	}

	// 4 nested maps should succeed: depth 0 -> 1 -> 2 -> 3 (all < 4).
	obj4 := map[string]any{
		"a": map[string]any{
			"b": map[string]any{
				"c": map[string]any{
					"d": "ok",
				},
			},
		},
	}
	got, err := Canonicalize(obj4)
	if err != nil {
		t.Fatalf("4 nested maps should succeed: %v", err)
	}
	want := `{"a":{"b":{"c":{"d":"ok"}}}}`
	if string(got) != want {
		t.Errorf("got %q, want %q", string(got), want)
	}
}

func TestCanonicalizeStringEscapes(t *testing.T) {
	tests := []struct {
		name string
		obj  map[string]any
		want string
	}{
		{"SpecialChars", map[string]any{"msg": "hello\nworld\t\"quoted\""}, `{"msg":"hello\nworld\t\"quoted\""}`},
		// U+0001 should be escaped as \u0001
		{"ControlChars", map[string]any{"val": "\x01"}, `{"val":"\u0001"}`},
		{"Backspace", map[string]any{"val": "\b"}, `{"val":"\b"}`},
		{"FormFeed", map[string]any{"val": "\f"}, `{"val":"\f"}`},
		{"CarriageReturn", map[string]any{"val": "\r"}, `{"val":"\r"}`},
		{"ForwardSlashNotEscaped", map[string]any{"path": "/foo/bar"}, `{"path":"/foo/bar"}`},
		{"Backslash", map[string]any{"val": `back\slash`}, `{"val":"back\\slash"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Canonicalize(tt.obj)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("got %q, want %q", string(got), tt.want)
			}
		})
	}
}

func TestCanonicalizeOutput(t *testing.T) {
	tests := []struct {
		name string
		obj  map[string]any
		want string
	}{
		{"EmptyObject", map[string]any{}, `{}`},
		{"EmptyArray", map[string]any{"arr": []any{}}, `{"arr":[]}`},
		{"Numbers", map[string]any{"int": float64(42), "zero": float64(0)}, `{"int":42,"zero":0}`},
		// Go int values should also work.
		{"IntType", map[string]any{"val": 42}, `{"val":42}`},
		{"Booleans", map[string]any{"f": false, "t": true}, `{"f":false,"t":true}`},
		{"ArrayInArray", map[string]any{"matrix": []any{
			[]any{float64(1), float64(2)},
			[]any{float64(3), float64(4)},
		}}, `{"matrix":[[1,2],[3,4]]}`},
		{"GeorgianText", map[string]any{"name": "ქართველი"}, `{"name":"ქართველი"}`},
		{"NestedArraysAndObjects", map[string]any{"items": []any{float64(1), "two", true, nil}}, `{"items":[1,"two",true,null]}`},
		{"FormatNumberSuccess 1e15", map[string]any{"val": 1e15}, `{"val":1000000000000000}`},
		{"FormatNumberSuccess 1.0", map[string]any{"val": 1.0}, `{"val":1}`},
		{"FormatNumberSuccess 100.0", map[string]any{"val": 100.0}, `{"val":100}`},
		{"FormatNumberSuccess -1.0", map[string]any{"val": -1.0}, `{"val":-1}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Canonicalize(tt.obj)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("got %q, want %q", string(got), tt.want)
			}
		})
	}
}

func TestCanonicalizeArrayDepthLimit(t *testing.T) {
	// Build deeply nested array that exceeds maxDepth.
	// depth 0: top-level map, depth 1: outer array, depth 2: inner1,
	// depth 3: inner2, depth 4: inner3 — rejected.
	inner := []any{"deep"}
	for i := 0; i < 3; i++ {
		inner = []any{inner}
	}
	obj := map[string]any{"arr": inner}
	_, err := Canonicalize(obj)
	if err == nil {
		t.Error("expected depth limit error for deeply nested array")
	}
}

func TestCanonicalizeArrayJustUnderDepthLimit(t *testing.T) {
	// depth 0: top-level map, depth 1: outer array, depth 2: inner1,
	// depth 3: inner2 — should succeed (3 < maxDepth=4).
	inner := []any{"ok"}
	for i := 0; i < 2; i++ {
		inner = []any{inner}
	}
	obj := map[string]any{"arr": inner}
	got, err := Canonicalize(obj)
	if err != nil {
		t.Fatalf("expected success for array at depth 3: %v", err)
	}
	want := `{"arr":[[["ok"]]]}`
	if string(got) != want {
		t.Errorf("got %q, want %q", string(got), want)
	}
}

func TestCanonicalizeSafeIntBoundary(t *testing.T) {
	maxSafe := float64(1<<53 - 1)
	obj := map[string]any{"val": maxSafe}
	_, err := Canonicalize(obj)
	if err != nil {
		t.Fatalf("maxSafeInt should succeed: %v", err)
	}

	obj["val"] = -maxSafe
	_, err = Canonicalize(obj)
	if err != nil {
		t.Fatalf("-maxSafeInt should succeed: %v", err)
	}

	obj["val"] = maxSafe + 1
	_, err = Canonicalize(obj)
	if err == nil {
		t.Error("expected error for maxSafeInt + 1")
	}

	obj["val"] = -maxSafe - 1
	_, err = Canonicalize(obj)
	if err == nil {
		t.Error("expected error for -maxSafeInt - 1")
	}
}

func TestCanonicalizeKeysNotNormalized(t *testing.T) {
	// Keys should NOT be NFC-normalized, only values.
	// Use a decomposed key: e + combining acute = "e\u0301"
	obj := map[string]any{
		"e\u0301": "value",
	}
	got, err := Canonicalize(obj)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	// The key should stay decomposed (2 bytes for e + 2 bytes for combining acute in UTF-8)
	// while the value stays as-is since it's already NFC.
	gotStr := string(got)
	// Key "e\u0301" is e (0x65) + combining acute (0xCC 0x81) — 3 bytes, NOT composed.
	if gotStr != "{\"e\u0301\":\"value\"}" {
		t.Errorf("keys should not be NFC-normalized, got %q", gotStr)
	}
}

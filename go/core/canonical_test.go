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

func TestCanonicalizeKeySorting(t *testing.T) {
	obj := map[string]any{
		"z": float64(1),
		"a": float64(2),
		"m": float64(3),
	}
	got, err := Canonicalize(obj)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	want := `{"a":2,"m":3,"z":1}`
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

func TestCanonicalizeProtoRejection(t *testing.T) {
	obj := map[string]any{
		"__proto__": "bad",
	}
	_, err := Canonicalize(obj)
	if err == nil {
		t.Error("expected error for __proto__ key")
	}
}

func TestCanonicalizeNestedProtoRejection(t *testing.T) {
	obj := map[string]any{
		"a": map[string]any{
			"__proto__": "bad",
		},
	}
	_, err := Canonicalize(obj)
	if err == nil {
		t.Error("expected error for nested __proto__ key")
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

func TestCanonicalizeDepthExact(t *testing.T) {
	// The outermost map is at depth 0. A map at depth 4 should be rejected.
	// depth 0: top-level
	// depth 1: l1
	// depth 2: l2
	// depth 3: l3
	// depth 4: l4 — rejected because depth >= maxDepth(4)
	obj := map[string]any{
		"l1": map[string]any{
			"l2": map[string]any{
				"l3": map[string]any{
					"l4": map[string]any{
						"val": "deep",
					},
				},
			},
		},
	}
	_, err := Canonicalize(obj)
	if err == nil {
		t.Error("expected depth limit error at depth 4")
	}

	// Just under the limit: innermost map at depth 3
	objOk := map[string]any{
		"l1": map[string]any{
			"l2": map[string]any{
				"l3": map[string]any{
					"val": "ok",
				},
			},
		},
	}
	_, err = Canonicalize(objOk)
	if err != nil {
		t.Fatalf("depth 3 inner map should succeed: %v", err)
	}
}

func TestCanonicalizeNegativeZero(t *testing.T) {
	obj := map[string]any{
		"val": math.Copysign(0, -1),
	}
	_, err := Canonicalize(obj)
	if err == nil {
		t.Error("expected error for negative zero")
	}
}

func TestCanonicalizeNaN(t *testing.T) {
	obj := map[string]any{
		"val": math.NaN(),
	}
	_, err := Canonicalize(obj)
	if err == nil {
		t.Error("expected error for NaN")
	}
}

func TestCanonicalizeInfinity(t *testing.T) {
	obj := map[string]any{
		"val": math.Inf(1),
	}
	_, err := Canonicalize(obj)
	if err == nil {
		t.Error("expected error for +Infinity")
	}

	obj["val"] = math.Inf(-1)
	_, err = Canonicalize(obj)
	if err == nil {
		t.Error("expected error for -Infinity")
	}
}

func TestCanonicalizeNestedArraysAndObjects(t *testing.T) {
	obj := map[string]any{
		"items": []any{float64(1), "two", true, nil},
	}
	got, err := Canonicalize(obj)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	want := `{"items":[1,"two",true,null]}`
	if string(got) != want {
		t.Errorf("got %q, want %q", string(got), want)
	}
}

func TestCanonicalizeSpecialChars(t *testing.T) {
	obj := map[string]any{
		"msg": "hello\nworld\t\"quoted\"",
	}
	got, err := Canonicalize(obj)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	want := `{"msg":"hello\nworld\t\"quoted\""}`
	if string(got) != want {
		t.Errorf("got %q, want %q", string(got), want)
	}
}

func TestCanonicalizeControlChars(t *testing.T) {
	// U+0001 should be escaped as \u0001
	obj := map[string]any{
		"val": "\x01",
	}
	got, err := Canonicalize(obj)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	want := `{"val":"\u0001"}`
	if string(got) != want {
		t.Errorf("got %q, want %q", string(got), want)
	}
}

func TestCanonicalizeBackspace(t *testing.T) {
	obj := map[string]any{
		"val": "\b",
	}
	got, err := Canonicalize(obj)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	want := `{"val":"\b"}`
	if string(got) != want {
		t.Errorf("got %q, want %q", string(got), want)
	}
}

func TestCanonicalizeFormFeed(t *testing.T) {
	obj := map[string]any{
		"val": "\f",
	}
	got, err := Canonicalize(obj)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	want := `{"val":"\f"}`
	if string(got) != want {
		t.Errorf("got %q, want %q", string(got), want)
	}
}

func TestCanonicalizeCarriageReturn(t *testing.T) {
	obj := map[string]any{
		"val": "\r",
	}
	got, err := Canonicalize(obj)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	want := `{"val":"\r"}`
	if string(got) != want {
		t.Errorf("got %q, want %q", string(got), want)
	}
}

func TestCanonicalizeForwardSlashNotEscaped(t *testing.T) {
	obj := map[string]any{
		"path": "/foo/bar",
	}
	got, err := Canonicalize(obj)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	want := `{"path":"/foo/bar"}`
	if string(got) != want {
		t.Errorf("got %q, want %q", string(got), want)
	}
}

func TestCanonicalizeEmptyObject(t *testing.T) {
	got, err := Canonicalize(map[string]any{})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if string(got) != "{}" {
		t.Errorf("got %q, want %q", string(got), "{}")
	}
}

func TestCanonicalizeEmptyArray(t *testing.T) {
	obj := map[string]any{
		"arr": []any{},
	}
	got, err := Canonicalize(obj)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	want := `{"arr":[]}`
	if string(got) != want {
		t.Errorf("got %q, want %q", string(got), want)
	}
}

func TestCanonicalizeErrorInArray(t *testing.T) {
	// An unsupported type inside an array should propagate the error.
	obj := map[string]any{
		"arr": []any{"ok", complex(1, 2)},
	}
	_, err := Canonicalize(obj)
	if err == nil {
		t.Error("expected error for unsupported type in array")
	}
}

func TestCanonicalizeGeorgianText(t *testing.T) {
	obj := map[string]any{
		"name": "ქართველი",
	}
	got, err := Canonicalize(obj)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	want := `{"name":"ქართველი"}`
	if string(got) != want {
		t.Errorf("got %q, want %q", string(got), want)
	}
}

func TestCanonicalizeNumbers(t *testing.T) {
	obj := map[string]any{
		"int":  float64(42),
		"zero": float64(0),
	}
	got, err := Canonicalize(obj)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	want := `{"int":42,"zero":0}`
	if string(got) != want {
		t.Errorf("got %q, want %q", string(got), want)
	}
}

func TestCanonicalizeNonIntegerFloatError(t *testing.T) {
	obj := map[string]any{"val": float64(1.5)}
	_, err := Canonicalize(obj)
	if err == nil {
		t.Error("expected error for non-integer float 1.5")
	}
}

func TestCanonicalizeIntType(t *testing.T) {
	// Go int values should also work.
	obj := map[string]any{
		"val": 42,
	}
	got, err := Canonicalize(obj)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	want := `{"val":42}`
	if string(got) != want {
		t.Errorf("got %q, want %q", string(got), want)
	}
}

func TestCanonicalizeNullValue(t *testing.T) {
	obj := map[string]any{
		"val": nil,
	}
	got, err := Canonicalize(obj)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	want := `{"val":null}`
	if string(got) != want {
		t.Errorf("got %q, want %q", string(got), want)
	}
}

func TestCanonicalizeBooleans(t *testing.T) {
	obj := map[string]any{
		"f": false,
		"t": true,
	}
	got, err := Canonicalize(obj)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	want := `{"f":false,"t":true}`
	if string(got) != want {
		t.Errorf("got %q, want %q", string(got), want)
	}
}

func TestCanonicalizeUnsupportedType(t *testing.T) {
	obj := map[string]any{
		"val": complex(1, 2),
	}
	_, err := Canonicalize(obj)
	if err == nil {
		t.Error("expected error for unsupported type")
	}
}

func TestCanonicalizeNestedObject(t *testing.T) {
	obj := map[string]any{
		"a": map[string]any{
			"b": map[string]any{
				"c": "deep",
			},
		},
	}
	got, err := Canonicalize(obj)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	want := `{"a":{"b":{"c":"deep"}}}`
	if string(got) != want {
		t.Errorf("got %q, want %q", string(got), want)
	}
}

func TestCanonicalizeBackslash(t *testing.T) {
	obj := map[string]any{
		"val": `back\slash`,
	}
	got, err := Canonicalize(obj)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	want := `{"val":"back\\slash"}`
	if string(got) != want {
		t.Errorf("got %q, want %q", string(got), want)
	}
}

func TestCanonicalizeArrayInArray(t *testing.T) {
	obj := map[string]any{
		"matrix": []any{
			[]any{float64(1), float64(2)},
			[]any{float64(3), float64(4)},
		},
	}
	got, err := Canonicalize(obj)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	want := `{"matrix":[[1,2],[3,4]]}`
	if string(got) != want {
		t.Errorf("got %q, want %q", string(got), want)
	}
}

func TestFormatNumberErrors(t *testing.T) {
	tests := []struct {
		name string
		val  float64
	}{
		{"large exponent", 1e20},
		{"small negative exponent", 1e-7},
		{"half", 0.5},
		{"max float64", math.MaxFloat64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := map[string]any{"val": tt.val}
			_, err := Canonicalize(obj)
			if err == nil {
				t.Errorf("expected error for %v", tt.val)
			}
		})
	}
}

func TestFormatNumberSuccess(t *testing.T) {
	tests := []struct {
		name string
		val  float64
		want string
	}{
		{"1e15", 1e15, "1000000000000000"},
		{"1.0", 1.0, "1"},
		{"100.0", 100.0, "100"},
		{"-1.0", -1.0, "-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := map[string]any{"val": tt.val}
			got, err := Canonicalize(obj)
			if err != nil {
				t.Fatalf("unexpected error for %v: %v", tt.val, err)
			}
			want := `{"val":` + tt.want + `}`
			if string(got) != want {
				t.Errorf("got %q, want %q", string(got), want)
			}
		})
	}
}

func TestCanonicalizeInvalidUTF8Value(t *testing.T) {
	obj := map[string]any{
		"val": "hello\xffworld",
	}
	_, err := Canonicalize(obj)
	if err == nil {
		t.Error("expected error for invalid UTF-8 in string value")
	}
}

func TestCanonicalizeInvalidUTF8Key(t *testing.T) {
	obj := map[string]any{
		"bad\xffkey": "value",
	}
	_, err := Canonicalize(obj)
	if err == nil {
		t.Error("expected error for invalid UTF-8 in object key")
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

func TestCanonicalizeArrayAtExactDepthLimit(t *testing.T) {
	// depth 0: map, depth 1: arr1, depth 2: arr2, depth 3: arr3,
	// depth 4: arr4 — rejected (depth >= maxDepth).
	var v any = []any{"val"}
	for i := 0; i < 3; i++ {
		v = []any{v}
	}
	obj := map[string]any{"a": v}
	_, err := Canonicalize(obj)
	if err == nil {
		t.Error("expected depth limit error for array at depth 4")
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

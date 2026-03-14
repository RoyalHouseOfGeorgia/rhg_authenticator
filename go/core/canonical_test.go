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
		"frac": float64(1.5),
	}
	got, err := Canonicalize(obj)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	want := `{"frac":1.5,"int":42,"zero":0}`
	if string(got) != want {
		t.Errorf("got %q, want %q", string(got), want)
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

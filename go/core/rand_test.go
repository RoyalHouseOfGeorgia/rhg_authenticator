package core

import "testing"

func TestRandomHex_Length(t *testing.T) {
	for _, n := range []int{0, 1, 2, 8, 15, 16, 32} {
		s, err := RandomHex(n)
		if err != nil {
			t.Fatalf("RandomHex(%d) error: %v", n, err)
		}
		if len(s) != n {
			t.Errorf("RandomHex(%d) = %q (len %d), want len %d", n, s, len(s), n)
		}
	}
}

func TestRandomHex_HexCharsOnly(t *testing.T) {
	s, err := RandomHex(32)
	if err != nil {
		t.Fatalf("RandomHex(32) error: %v", err)
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("non-hex character %q in %q", c, s)
		}
	}
}

func TestRandomHex_Uniqueness(t *testing.T) {
	a, _ := RandomHex(16)
	b, _ := RandomHex(16)
	if a == b {
		t.Errorf("two calls returned identical results: %q", a)
	}
}

func TestRandomHex_Negative(t *testing.T) {
	_, err := RandomHex(-1)
	if err == nil {
		t.Fatal("expected error for negative n")
	}
}

func TestRandomHex_Zero(t *testing.T) {
	s, err := RandomHex(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s != "" {
		t.Errorf("RandomHex(0) = %q, want empty", s)
	}
}

func TestRandomHex_OddN(t *testing.T) {
	s, err := RandomHex(7)
	if err != nil {
		t.Fatalf("RandomHex(7) error: %v", err)
	}
	if len(s) != 7 {
		t.Errorf("len = %d, want 7", len(s))
	}
}

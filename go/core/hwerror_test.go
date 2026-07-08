package core

import (
	"fmt"
	"testing"
)

func TestClassifyHardwareError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		// Smartcard patterns
		{name: "pcsc lowercase", err: fmt.Errorf("pcsc daemon not running"), want: HwErrSmartcard},
		{name: "PCSC uppercase", err: fmt.Errorf("PCSC service unavailable"), want: HwErrSmartcard},
		{name: "pcsc mixed case", err: fmt.Errorf("PCSc error"), want: HwErrSmartcard},
		{name: "scard word boundary", err: fmt.Errorf("scard: service unavailable"), want: HwErrSmartcard},
		{name: "SCard mixed case", err: fmt.Errorf("SCard error occurred"), want: HwErrSmartcard},

		// PIN patterns
		{name: "PIN uppercase", err: fmt.Errorf("wrong PIN entered"), want: HwErrPIN},
		{name: "PIN locked", err: fmt.Errorf("PIN locked"), want: HwErrPIN},
		{name: "pin lowercase", err: fmt.Errorf("invalid pin provided"), want: HwErrPIN},
		{name: "Pin mixed case", err: fmt.Errorf("Pin verification failed"), want: HwErrPIN},

		// Hardware patterns
		{name: "yubikey lowercase", err: fmt.Errorf("no yubikey detected"), want: HwErrHardware},
		{name: "YubiKey mixed case", err: fmt.Errorf("no YubiKey detected"), want: HwErrHardware},
		{name: "smart card", err: fmt.Errorf("smart card not found"), want: HwErrHardware},
		{name: "Smart Card mixed", err: fmt.Errorf("Smart Card reader error"), want: HwErrHardware},

		// No match
		{name: "generic error", err: fmt.Errorf("unexpected failure"), want: ""},
		{name: "nil error", err: nil, want: ""},
		{name: "empty error", err: fmt.Errorf(""), want: ""},

		// False positives: scard embedded in other words
		{name: "discard (no false positive)", err: fmt.Errorf("discard old data"), want: ""},

		// False positives: pin embedded in other words
		{name: "spinning (no false positive)", err: fmt.Errorf("spinning up"), want: ""},
		{name: "hairpin (no false positive)", err: fmt.Errorf("hairpin turn"), want: ""},
		{name: "pinot (no false positive)", err: fmt.Errorf("pinot noir"), want: ""},
		{name: "opinionated (no false positive)", err: fmt.Errorf("opinionated design"), want: ""},

		// Priority: pcsc/scard before pin
		{name: "pcsc trumps pin", err: fmt.Errorf("pcsc PIN error"), want: HwErrSmartcard},
		{name: "scard trumps pin", err: fmt.Errorf("scard: wrong PIN"), want: HwErrSmartcard},

		// Transient PC/SC contention patterns (one per phrase, full pcsc strings)
		{name: "smart card reset", err: fmt.Errorf("the smart card has been reset, so any shared state information is invalid"), want: HwErrTransient},
		{name: "smart card removed", err: fmt.Errorf("the smart card has been removed, so further communication is not possible"), want: HwErrTransient},
		{name: "smart card unpowered", err: fmt.Errorf("power has been removed from the smart card, so that further communication is not possible"), want: HwErrTransient},
		{name: "smart card not responding to reset", err: fmt.Errorf("the smart card is not responding to a reset"), want: HwErrTransient},
		{name: "non-existent transaction", err: fmt.Errorf("an attempt was made to end a non-existent transaction"), want: HwErrTransient},

		// Priority: reset trumps pin (real wrapped chain contains both "verify pin" and reset phrase)
		{name: "reset trumps pin", err: fmt.Errorf("sign: signing failed: verify pin: transmitting request: the smart card has been reset, so any shared state information is invalid"), want: HwErrTransient},

		// Negative: anchored on "smart card has been reset", so a bare reset stays PIN
		{name: "PIN has been reset (not transient)", err: fmt.Errorf("PIN has been reset"), want: HwErrPIN},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyHardwareError(tt.err)
			if got != tt.want {
				t.Errorf("ClassifyHardwareError(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

func TestContainsAny(t *testing.T) {
	subs := []string{"foo", "bar"}
	tests := []struct {
		name string
		s    string
		subs []string
		want bool
	}{
		{name: "matches first sub", s: "a foo b", subs: subs, want: true},
		{name: "matches second sub", s: "a bar b", subs: subs, want: true},
		{name: "no match", s: "a baz b", subs: subs, want: false},
		{name: "empty subs", s: "anything", subs: nil, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsAny(tt.s, tt.subs); got != tt.want {
				t.Errorf("containsAny(%q, %v) = %v, want %v", tt.s, tt.subs, got, tt.want)
			}
		})
	}
}

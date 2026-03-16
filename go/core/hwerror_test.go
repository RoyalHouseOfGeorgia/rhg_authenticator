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

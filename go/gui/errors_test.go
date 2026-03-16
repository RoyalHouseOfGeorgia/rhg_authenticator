package gui

import (
	"fmt"
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

func TestClassifyHardwareError_PCSC(t *testing.T) {
	got := classifyHardwareError(fmt.Errorf("pcsc daemon not running"))
	if got != core.HwErrSmartcard {
		t.Errorf("got %q, want %q", got, core.HwErrSmartcard)
	}
}

func TestClassifyHardwareError_SCARD(t *testing.T) {
	got := classifyHardwareError(fmt.Errorf("scard: service unavailable"))
	if got != core.HwErrSmartcard {
		t.Errorf("got %q, want %q", got, core.HwErrSmartcard)
	}
}

func TestClassifyHardwareError_PIN(t *testing.T) {
	got := classifyHardwareError(fmt.Errorf("wrong PIN entered"))
	if got != core.HwErrPIN {
		t.Errorf("got %q, want %q", got, core.HwErrPIN)
	}
}

func TestClassifyHardwareError_YubiKey(t *testing.T) {
	got := classifyHardwareError(fmt.Errorf("no YubiKey detected"))
	if got != core.HwErrHardware {
		t.Errorf("got %q, want %q", got, core.HwErrHardware)
	}
}

func TestClassifyHardwareError_Card(t *testing.T) {
	got := classifyHardwareError(fmt.Errorf("smart card not found"))
	if got != core.HwErrHardware {
		t.Errorf("got %q, want %q", got, core.HwErrHardware)
	}
}

func TestClassifyHardwareError_Generic(t *testing.T) {
	got := classifyHardwareError(fmt.Errorf("unexpected failure"))
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestClassifyHardwareError_Nil(t *testing.T) {
	got := classifyHardwareError(nil)
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestClassifyHardwareError_PINLocked(t *testing.T) {
	got := classifyHardwareError(fmt.Errorf("PIN locked"))
	if got != core.HwErrPIN {
		t.Errorf("got %q, want %q", got, core.HwErrPIN)
	}
}

func TestClassifyHardwareError_NoFalsePositive_Discard(t *testing.T) {
	got := classifyHardwareError(fmt.Errorf("discard old data"))
	if got != "" {
		t.Errorf("got %q, want empty for 'discard old data'", got)
	}
}

func TestClassifyHardwareError_NoFalsePositive_Spinning(t *testing.T) {
	got := classifyHardwareError(fmt.Errorf("spinning up"))
	if got != "" {
		t.Errorf("got %q, want empty for 'spinning up'", got)
	}
}

func TestClassifyHardwareError_NoFalsePositive_Hairpin(t *testing.T) {
	got := classifyHardwareError(fmt.Errorf("hairpin turn"))
	if got != "" {
		t.Errorf("got %q, want empty for 'hairpin turn'", got)
	}
}

func TestClassifyHardwareError_NoFalsePositive_Pinot(t *testing.T) {
	got := classifyHardwareError(fmt.Errorf("pinot noir"))
	if got != "" {
		t.Errorf("got %q, want empty for 'pinot noir'", got)
	}
}

package buildinfo

import (
	"bytes"
	"image/png"
	"os"
	"testing"
)

// TestAppIconIsSquare1024 guards go/icon.png, which scripts/build-macos-app.sh
// turns into the macOS .icns and from which the Windows app.ico was generated.
func TestAppIconIsSquare1024(t *testing.T) {
	data, err := os.ReadFile("../icon.png")
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("icon.png does not decode as PNG: %v", err)
	}
	if b := img.Bounds(); b.Dx() != 1024 || b.Dy() != 1024 {
		t.Errorf("icon.png is %dx%d, want 1024x1024 (see DEVELOPER.md \"App Icon\")", b.Dx(), b.Dy())
	}
	if _, _, _, a := img.At(0, 0).RGBA(); a != 0 {
		t.Error("icon.png corner is not transparent; it needs an alpha channel and margin")
	}
}

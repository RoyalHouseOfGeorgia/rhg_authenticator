package qr

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const testURL = "https://example.com/verify?id=abc123"

func TestGenerateSVGValidXML(t *testing.T) {
	svg, err := GenerateSVG(testURL)
	if err != nil {
		t.Fatalf("GenerateSVG error: %v", err)
	}

	// Verify well-formed XML.
	if err := xml.Unmarshal(svg, new(any)); err != nil {
		t.Fatalf("SVG is not valid XML: %v", err)
	}
}

func TestGenerateSVGViewBox(t *testing.T) {
	svg, err := GenerateSVG(testURL)
	if err != nil {
		t.Fatalf("GenerateSVG error: %v", err)
	}

	// Extract viewBox dimensions and verify they match N+8.
	re := regexp.MustCompile(`viewBox="0 0 (\d+) (\d+)"`)
	matches := re.FindSubmatch(svg)
	if matches == nil {
		t.Fatal("viewBox not found in SVG")
	}

	w, _ := strconv.Atoi(string(matches[1]))
	h, _ := strconv.Atoi(string(matches[2]))
	if w != h {
		t.Errorf("viewBox not square: %d x %d", w, h)
	}

	// N+8 must be even: N = modules, so total = N+8.
	// Verify by checking that (total - 8) > 0.
	n := w - 8
	if n <= 0 {
		t.Errorf("module count N=%d should be positive", n)
	}
}

func TestGenerateSVGViewBoxMatchesModuleCount(t *testing.T) {
	svg, err := GenerateSVG(testURL)
	if err != nil {
		t.Fatalf("GenerateSVG error: %v", err)
	}

	// Count dark module rects to find the max x and y coordinates.
	re := regexp.MustCompile(`viewBox="0 0 (\d+) (\d+)"`)
	matches := re.FindSubmatch(svg)
	if matches == nil {
		t.Fatal("viewBox not found")
	}
	viewBoxSize, _ := strconv.Atoi(string(matches[1]))

	// The viewBox should be N+8 where N is module count.
	// Verify by independently counting: find the maximum coordinate used
	// in dark module rects — it should be < viewBoxSize - 4 (quiet zone).
	rectRe := regexp.MustCompile(`<rect x="(\d+)" y="(\d+)" width="1" height="1" fill="black"/>`)
	rectMatches := rectRe.FindAllSubmatch(svg, -1)
	if len(rectMatches) == 0 {
		t.Fatal("no dark modules found")
	}

	maxCoord := 0
	for _, m := range rectMatches {
		x, _ := strconv.Atoi(string(m[1]))
		y, _ := strconv.Atoi(string(m[2]))
		if x > maxCoord {
			maxCoord = x
		}
		if y > maxCoord {
			maxCoord = y
		}
	}

	// maxCoord should be at most (N-1)+4 = viewBoxSize - 5
	expectedMax := viewBoxSize - 5
	if maxCoord > expectedMax {
		t.Errorf("max dark module coord %d exceeds expected %d", maxCoord, expectedMax)
	}
}

func TestGenerateSVGWhiteBackground(t *testing.T) {
	svg, err := GenerateSVG(testURL)
	if err != nil {
		t.Fatalf("GenerateSVG error: %v", err)
	}

	if !bytes.Contains(svg, []byte(`fill="white"`)) {
		t.Error("SVG missing white background rect")
	}

	// The white rect should come before any black rects.
	whiteIdx := bytes.Index(svg, []byte(`fill="white"`))
	blackIdx := bytes.Index(svg, []byte(`fill="black"`))
	if blackIdx >= 0 && whiteIdx > blackIdx {
		t.Error("white background rect should appear before dark modules")
	}
}

func TestGenerateSVGDarkModules(t *testing.T) {
	svg, err := GenerateSVG(testURL)
	if err != nil {
		t.Fatalf("GenerateSVG error: %v", err)
	}

	count := bytes.Count(svg, []byte(`fill="black"`))
	if count == 0 {
		t.Error("SVG should contain at least one dark module rect")
	}
}

func TestGenerateSVGExactLengthLimit(t *testing.T) {
	// URL exactly at 625 chars should succeed.
	url := "https://example.com/" + strings.Repeat("x", QRMaxURLLength-len("https://example.com/"))
	if len(url) != QRMaxURLLength {
		t.Fatalf("test setup: URL length is %d, want %d", len(url), QRMaxURLLength)
	}

	_, err := GenerateSVG(url)
	if err != nil {
		t.Errorf("URL at exactly %d chars should succeed: %v", QRMaxURLLength, err)
	}
}

func TestGenerateSVGOverLengthLimit(t *testing.T) {
	url := strings.Repeat("x", QRMaxURLLength+1)
	_, err := GenerateSVG(url)
	if err == nil {
		t.Error("expected error for URL exceeding max length")
	}
	if err != nil && !strings.Contains(err.Error(), "exceeds maximum") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGenerateSVGEmptyURL(t *testing.T) {
	// The go-qrcode library rejects empty data with "no data to encode".
	_, err := GenerateSVG("")
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestGeneratePNGHeader(t *testing.T) {
	png, err := GeneratePNG(testURL, 256)
	if err != nil {
		t.Fatalf("GeneratePNG error: %v", err)
	}

	// PNG files start with the 8-byte signature: \x89PNG\r\n\x1a\n
	pngHeader := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	if !bytes.HasPrefix(png, pngHeader) {
		t.Error("output does not have PNG header signature")
	}
}

func TestGeneratePNGWidth512(t *testing.T) {
	png, err := GeneratePNG(testURL, 512)
	if err != nil {
		t.Fatalf("GeneratePNG error: %v", err)
	}

	if len(png) == 0 {
		t.Error("PNG bytes should not be empty")
	}

	// Verify PNG header.
	pngHeader := []byte{0x89, 0x50, 0x4E, 0x47}
	if !bytes.HasPrefix(png, pngHeader) {
		t.Error("output does not start with PNG magic bytes")
	}
}

func TestGeneratePNGOverLengthLimit(t *testing.T) {
	url := strings.Repeat("x", QRMaxURLLength+1)
	_, err := GeneratePNG(url, 256)
	if err == nil {
		t.Error("expected error for URL exceeding max length")
	}
}

func TestSaveSVGWritesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.svg")

	if err := SaveSVG(testURL, path); err != nil {
		t.Fatalf("SaveSVG error: %v", err)
	}

	// File should exist.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("file not created: %v", err)
	}
	if info.Size() == 0 {
		t.Error("SVG file should not be empty")
	}

	// Content should match GenerateSVG output.
	fileContent, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading file: %v", err)
	}
	expected, err := GenerateSVG(testURL)
	if err != nil {
		t.Fatalf("GenerateSVG for comparison: %v", err)
	}
	if !bytes.Equal(fileContent, expected) {
		t.Error("SaveSVG file content does not match GenerateSVG output")
	}
}

func TestSaveSVGFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.svg")

	if err := SaveSVG(testURL, path); err != nil {
		t.Fatalf("SaveSVG error: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("file not created: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("file permissions = %04o, want 0600", perm)
	}
}

func TestSaveSVGInvalidPath(t *testing.T) {
	err := SaveSVG(testURL, "/nonexistent/dir/test.svg")
	if err == nil {
		t.Error("expected error for invalid path")
	}
}

func TestSaveSVGOverLengthLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.svg")
	url := strings.Repeat("x", QRMaxURLLength+1)

	err := SaveSVG(url, path)
	if err == nil {
		t.Error("expected error for URL exceeding max length")
	}

	// File should not exist.
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("file should not be created when URL is too long")
	}
}

func TestGeneratePNGEmptyURL(t *testing.T) {
	// The go-qrcode library rejects empty data with "no data to encode".
	_, err := GeneratePNG("", 256)
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestNewQRValid(t *testing.T) {
	qr, err := newQR(testURL)
	if err != nil {
		t.Fatalf("newQR error: %v", err)
	}
	if qr == nil {
		t.Fatal("newQR returned nil QRCode")
	}
}

func TestNewQRExactLimit(t *testing.T) {
	url := "https://example.com/" + strings.Repeat("x", QRMaxURLLength-len("https://example.com/"))
	if len(url) != QRMaxURLLength {
		t.Fatalf("test setup: URL length is %d, want %d", len(url), QRMaxURLLength)
	}
	qr, err := newQR(url)
	if err != nil {
		t.Fatalf("newQR should succeed at exactly %d chars: %v", QRMaxURLLength, err)
	}
	if qr == nil {
		t.Fatal("newQR returned nil QRCode")
	}
}

func TestNewQROverLimit(t *testing.T) {
	url := strings.Repeat("x", QRMaxURLLength+1)
	_, err := newQR(url)
	if err == nil {
		t.Fatal("expected error for URL exceeding max length")
	}
	expected := fmt.Sprintf("URL exceeds maximum length (%d > %d)", QRMaxURLLength+1, QRMaxURLLength)
	if err.Error() != expected {
		t.Errorf("error = %q, want %q", err.Error(), expected)
	}
}

func TestNewQREmpty(t *testing.T) {
	_, err := newQR("")
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestQRMaxURLLengthConstant(t *testing.T) {
	if QRMaxURLLength != 625 {
		t.Errorf("QRMaxURLLength = %d, want 625", QRMaxURLLength)
	}
}

func TestGenerateSVGXMLDeclaration(t *testing.T) {
	svg, err := GenerateSVG(testURL)
	if err != nil {
		t.Fatalf("GenerateSVG error: %v", err)
	}

	if !bytes.HasPrefix(svg, []byte(`<?xml version="1.0" encoding="UTF-8"?>`)) {
		t.Error("SVG should start with XML declaration")
	}
}

func TestGenerateSVGSVGNamespace(t *testing.T) {
	svg, err := GenerateSVG(testURL)
	if err != nil {
		t.Fatalf("GenerateSVG error: %v", err)
	}

	if !bytes.Contains(svg, []byte(`xmlns="http://www.w3.org/2000/svg"`)) {
		t.Error("SVG should contain SVG namespace declaration")
	}
}

func TestGenerateSVGQuietZoneOffset(t *testing.T) {
	svg, err := GenerateSVG(testURL)
	if err != nil {
		t.Fatalf("GenerateSVG error: %v", err)
	}

	// All dark module rects should have x >= 4 and y >= 4 (quiet zone offset).
	rectRe := regexp.MustCompile(`<rect x="(\d+)" y="(\d+)" width="1" height="1" fill="black"/>`)
	rectMatches := rectRe.FindAllSubmatch(svg, -1)
	if len(rectMatches) == 0 {
		t.Fatal("no dark modules found")
	}

	for _, m := range rectMatches {
		x, _ := strconv.Atoi(string(m[1]))
		y, _ := strconv.Atoi(string(m[2]))
		if x < 4 || y < 4 {
			t.Errorf("dark module at (%d, %d) violates 4-module quiet zone", x, y)
		}
	}
}

func TestGenerateSVGWhiteBackgroundRectSize(t *testing.T) {
	svg, err := GenerateSVG(testURL)
	if err != nil {
		t.Fatalf("GenerateSVG error: %v", err)
	}

	// The white background rect should match the viewBox dimensions.
	viewBoxRe := regexp.MustCompile(`viewBox="0 0 (\d+) (\d+)"`)
	vbMatch := viewBoxRe.FindSubmatch(svg)
	if vbMatch == nil {
		t.Fatal("viewBox not found")
	}
	total := string(vbMatch[1])

	expected := fmt.Sprintf(`<rect width="%s" height="%s" fill="white"/>`, total, total)
	if !bytes.Contains(svg, []byte(expected)) {
		t.Errorf("white background rect should match viewBox: expected %s", expected)
	}
}

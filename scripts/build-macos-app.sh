#!/usr/bin/env bash
# Builds the native macOS app (the Swift package in macos/) into an ad-hoc
# signed "RHG Authenticator.app" and zips it for the in-app updater:
#
#   RHGCORE_LIB_DIR=<dir> scripts/build-macos-app.sh [VERSION]
#
# RHGCORE_LIB_DIR is the RELEASE build of the rhgcore library (librhgcore.a +
# librhgcore.h, from scripts/rhgcore-smoke.sh: go/release/rhgcore/release).
# This script never builds Go itself. VERSION is CFBundleShortVersionString
# (X.Y.Z, default 0.0.0); CFBundleVersion is $GITHUB_RUN_NUMBER (default 1).
#
# Output: release/macos-app/rhg-authenticator-darwin-arm64.zip (the .app is
# removed once zipped). macOS only; works with macOS bash 3.2.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PACKAGE_DIR="$ROOT/macos"
SCRATCH="$PACKAGE_DIR/.build/lib-release"
OUT_DIR="$ROOT/release/macos-app"
APP="$OUT_DIR/RHG Authenticator.app"
ZIP_NAME="rhg-authenticator-darwin-arm64.zip"
VERSION="${1:-0.0.0}"
BUILD_NUMBER="${GITHUB_RUN_NUMBER:-1}"
MIN_MACOS=14.0

die() {
	echo "FAIL: $*" >&2
	exit 1
}

[ "$(uname -s)" = Darwin ] || die "macOS only"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "VERSION must be X.Y.Z, got '$VERSION'"
[[ "$BUILD_NUMBER" =~ ^[0-9]+$ ]] || die "GITHUB_RUN_NUMBER must be a number, got '$BUILD_NUMBER'"

[ -n "${RHGCORE_LIB_DIR:-}" ] ||
	die "set RHGCORE_LIB_DIR to the release rhgcore library (bash scripts/rhgcore-smoke.sh builds go/release/rhgcore/release)"
[ -d "$RHGCORE_LIB_DIR" ] || die "RHGCORE_LIB_DIR $RHGCORE_LIB_DIR is not a directory"
# Package.swift uses the path as is for -I and -L: make it absolute.
RHGCORE_LIB_DIR="$(cd "$RHGCORE_LIB_DIR" && pwd)"
export RHGCORE_LIB_DIR
for f in librhgcore.a librhgcore.h; do
	[ -f "$RHGCORE_LIB_DIR/$f" ] || die "$RHGCORE_LIB_DIR/$f not found"
done

echo "== swift build (release, library $RHGCORE_LIB_DIR)"
# A clean build: SwiftPM does not relink when only the library changes.
rm -rf "$SCRATCH"
SWIFT_ARGS=(-c release --package-path "$PACKAGE_DIR" --scratch-path "$SCRATCH" --product rhg-authenticator)
swift build "${SWIFT_ARGS[@]}"
BIN_DIR="$(swift build "${SWIFT_ARGS[@]}" --show-bin-path)"
[ -x "$BIN_DIR/rhg-authenticator" ] || die "built binary not found in $BIN_DIR"

echo "== assemble $APP"
rm -rf "$OUT_DIR"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN_DIR/rhg-authenticator" "$APP/Contents/MacOS/rhg-authenticator"
PLIST="$APP/Contents/Info.plist"
cp "$ROOT/go/packaging/macos/Info.plist" "$PLIST"
plutil -replace CFBundleShortVersionString -string "$VERSION" "$PLIST"
plutil -replace CFBundleVersion -string "$BUILD_NUMBER" "$PLIST"
plutil -replace LSMinimumSystemVersion -string "$MIN_MACOS" "$PLIST"
plutil -lint "$PLIST"

# go/icon.png is a 1024×1024 square with the standard ~10% margin.
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
ICONSET="$TMP_DIR/icon.iconset"
mkdir -p "$ICONSET"
for s in 16 32 128 256 512; do
	sips -z "$s" "$s" "$ROOT/go/icon.png" --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
	sips -z $((s * 2)) $((s * 2)) "$ROOT/go/icon.png" --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/icon.icns"

echo "== check the binary"
MAIN_BIN="$APP/Contents/MacOS/rhg-authenticator"
version_out="$("$MAIN_BIN" --version)" || die "--version exited non-zero"
echo "--version: $version_out"
[ -n "$version_out" ] || die "--version printed nothing"
case "$version_out" in
*rhgfake*) die "the app is linked with the rhgfake library: point RHGCORE_LIB_DIR at the release build" ;;
esac

build_info="$(vtool -show-build "$MAIN_BIN")" || die "vtool failed"
minos="$(awk '$1 == "minos" { print $2; exit }' <<<"$build_info")"
[ "$minos" = "$MIN_MACOS" ] || die "binary minos is '$minos', want $MIN_MACOS"
echo "minos: $minos"

echo "== sign (ad hoc)"
# Required: without a bundle signature, Gatekeeper on Apple Silicon reports
# the downloaded app as "damaged" with no "Open Anyway" option.
codesign --force --sign - "$APP"
codesign --verify --strict --verbose=2 "$APP"

echo "== zip"
# No resource forks, xattrs or quarantine: AppleDouble ._* / __MACOSX entries
# would fail the in-app updater's single-top-level-dir check.
(cd "$OUT_DIR" && ditto -c -k --norsrc --noextattr --noqtn --keepParent "RHG Authenticator.app" "$ZIP_NAME")
rm -rf "$APP"
echo "built $OUT_DIR/$ZIP_NAME"

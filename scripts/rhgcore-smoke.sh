#!/usr/bin/env bash
# Builds the rhgcore C library (release and rhgfake variants) and smoke-tests
# each through its C ABI with go/cmd/rhgcore/smoketest/smoke.c.
#
#   Linux, macOS: -buildmode=c-archive -> librhgcore.a + librhgcore.h, plus
#                 librhgcore.link (the linker flags a host app needs)
#   Windows (Git Bash): -buildmode=c-shared -> rhgcore.dll + rhgcore.h
#
# Outputs go to go/release/rhgcore/release/ and go/release/rhgcore/rhgfake/.
# RHGCORE_VERSION sets the embedded version (default "dev"; no spaces).
# Works with macOS bash 3.2 and Git Bash.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GO_DIR="$ROOT/go"
SMOKE_SRC="$GO_DIR/cmd/rhgcore/smoketest/smoke.c"
OUT_BASE="$GO_DIR/release/rhgcore"
VERSION="${RHGCORE_VERSION:-dev}"
LDFLAGS="-w -X github.com/royalhouseofgeorgia/rhg-authenticator/buildinfo.Version=$VERSION"

case "$(uname -s)" in
Linux) OS=linux ;;
Darwin) OS=macos ;;
MINGW* | MSYS* | CYGWIN*) OS=windows ;;
*)
	echo "unsupported OS: $(uname -s)" >&2
	exit 1
	;;
esac

if [ "$OS" = macos ]; then
	export MACOSX_DEPLOYMENT_TARGET=14.0
fi

die() {
	echo "FAIL: $*" >&2
	exit 1
}

# link_flags prints the linker flags for the archive built with tags $1:
# every dependency's cgo LDFLAGS plus the OS's system libraries, each once
# ("-framework X" counts as one flag).
link_flags() {
	local tags="$1" derived
	derived="$(cd "$GO_DIR" && go list -tags "$tags" -deps -f '{{join .CgoLDFLAGS " "}}' ./cmd/rhgcore)"
	case "$OS" in
	linux) derived="-lpcsclite -lpthread $derived" ;;
	macos) derived="$derived -framework CoreFoundation -framework Security" ;;
	esac
	echo $derived | awk '{
		for (i = 1; i <= NF; i++) {
			f = $i
			if (f == "-framework" && i < NF) { i++; f = f " " $i }
			if (!(f in seen)) { seen[f] = 1; out = out (out == "" ? "" : " ") f }
		}
	} END { print out }'
}

# build_variant builds variant $1 ("release" or "rhgfake") with tags $2 into
# $OUT_BASE/$1.
build_variant() {
	local name="$1" tags="$2" out="$OUT_BASE/$1"
	rm -rf "$out"
	mkdir -p "$out"
	echo "== build $name ($OS)"
	if [ "$OS" = windows ]; then
		(cd "$GO_DIR" && go build -trimpath -buildmode=c-shared -tags "$tags" -ldflags "$LDFLAGS" \
			-o "$out/rhgcore.dll" ./cmd/rhgcore)
		[ -f "$out/rhgcore.h" ] || die "$name: rhgcore.h not generated"
	else
		(cd "$GO_DIR" && go build -trimpath -buildmode=c-archive -tags "$tags" -ldflags "$LDFLAGS" \
			-o "$out/librhgcore.a" ./cmd/rhgcore)
		[ -f "$out/librhgcore.h" ] || die "$name: librhgcore.h not generated"
		link_flags "$tags" >"$out/librhgcore.link"
		echo "link flags: $(cat "$out/librhgcore.link")"
	fi
}

# check_exports checks the library of variant $1 defines the four exports:
# the archive's symbols (nm), or the DLL's export table (objdump, MinGW).
check_exports() {
	local out="$OUT_BASE/$1" sym syms pattern
	# Captured and fed as a here-string: grep -q closing a pipe early would
	# fail the writer with SIGPIPE under pipefail.
	if [ "$OS" = windows ]; then
		syms="$(objdump -p "$out/rhgcore.dll")" || die "$1: objdump failed"
		pattern='[[:space:]]%s$'
	else
		syms="$(nm "$out/librhgcore.a")" || die "$1: nm failed"
		pattern=' T _?%s$'
	fi
	for sym in RHGCall RHGFree RHGSetEventCallback RHGMainCLI; do
		# shellcheck disable=SC2059 # the pattern is the format on purpose
		grep -Eq "$(printf "$pattern" "$sym")" <<<"$syms" || die "$1: $sym is not exported"
	done
	echo "exports: RHGCall RHGFree RHGSetEventCallback RHGMainCLI"
}

# compile_smoke builds the smoke binary for variant $1 and prints its path.
# It runs in a command substitution, where bash ignores set -e, so each
# failure exits explicitly.
compile_smoke() {
	local out="$OUT_BASE/$1"
	if [ "$OS" = windows ]; then
		gcc -I"$out" "$SMOKE_SRC" "$out/rhgcore.dll" -o "$out/smoke.exe" >&2 || die "$1: compiling smoke.c failed"
		echo "$out/smoke.exe"
	else
		# shellcheck disable=SC2046 # the link flags are word-split on purpose
		cc -I"$out" "$SMOKE_SRC" "$out/librhgcore.a" $(cat "$out/librhgcore.link") -o "$out/smoke" >&2 ||
			die "$1: compiling smoke.c failed"
		echo "$out/smoke"
	fi
}

# smoke_variant runs the smoke checks for variant $1 in a fresh data dir; $2
# is smoke.c's mode: "release", "fake-offline" or "fake-online".
smoke_variant() {
	local name="$1" mode="$2" bin version_out tmp_dir data_dir
	bin="$(compile_smoke "$name")"

	version_out="$("$bin" --version)" || die "$name: --version exited non-zero"
	echo "--version: $version_out"
	case "$version_out" in
	*"$VERSION"*) ;;
	*) die "$name: --version output lacks $VERSION" ;;
	esac
	case "$mode:$version_out" in
	fake-*:*rhgfake*) ;;
	fake-*:*) die "$name: --version output lacks rhgfake" ;;
	release:*rhgfake*) die "$name: release --version output contains rhgfake" ;;
	esac

	tmp_dir="$(mktemp -d)"
	trap 'rm -rf "$tmp_dir"' EXIT # die exits from here
	data_dir="$tmp_dir"
	if command -v cygpath >/dev/null 2>&1; then
		data_dir="$(cygpath -w "$tmp_dir")" # a native Windows path, backslashes and all
	fi
	"$bin" "$data_dir" "$mode" || die "$name: $mode smoke checks failed"
	rm -rf "$tmp_dir"
	trap - EXIT
}

build_variant release ""
build_variant rhgfake rhgfake
check_exports release
check_exports rhgfake
smoke_variant release release
smoke_variant rhgfake fake-offline
smoke_variant rhgfake fake-online
echo "rhgcore smoke: all checks passed"

module github.com/royalhouseofgeorgia/rhg-authenticator

go 1.27.3

require (
	github.com/go-piv/piv-go/v2 v2.6.0
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e // unmaintained (2020); TODO(2027): evaluate maintained alternative. Security audit 2026-03: no known CVEs, input is app-controlled.
	github.com/zalando/go-keyring v0.2.8
	golang.org/x/sys v0.49.0
	golang.org/x/text v0.43.0
)

require (
	github.com/danieljoos/wincred v1.2.3 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/telemetry v0.0.0-20260924152758-ed294f943157 // indirect
	golang.org/x/tools v0.51.0 // indirect
	golang.org/x/tools/go/packages/packagestest v0.1.1-deprecated // indirect
	golang.org/x/vuln v1.1.4 // indirect
)

tool golang.org/x/vuln/cmd/govulncheck

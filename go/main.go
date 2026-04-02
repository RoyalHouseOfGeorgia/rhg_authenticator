package main

import (
	"context"
	_ "embed"
	"fmt"
	"image/color"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"net/url"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/buildinfo"
	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
	"github.com/royalhouseofgeorgia/rhg-authenticator/errorreport"
	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
	"github.com/royalhouseofgeorgia/rhg-authenticator/gui"
	"github.com/royalhouseofgeorgia/rhg-authenticator/log"
	"github.com/royalhouseofgeorgia/rhg-authenticator/regmgr"
	"github.com/royalhouseofgeorgia/rhg-authenticator/registry"
	"github.com/royalhouseofgeorgia/rhg-authenticator/update"
)

//go:embed icon.png
var appIconData []byte

func main() {
	// Catch panics on the main goroutine. Spawned goroutines use safeGo.
	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			stack := string(buf[:n])
			// Best-effort write to debug.log (synchronous file I/O only).
			if configDir, err := os.UserConfigDir(); err == nil {
				logPath := filepath.Join(configDir, "rhg-authenticator", "debug.log")
				if f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
					fmt.Fprintf(f, "PANIC: %v\n%s\n", r, stack)
					f.Close()
				}
			}
			fmt.Fprintf(os.Stderr, "RHG Authenticator crashed. Please report at https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/issues\n\nPanic: %v\n%s\n", r, stack)
			panic(r) // re-panic so the OS gets the signal
		}
	}()

	// Handle --version before any GUI initialization.
	for _, arg := range os.Args[1:] {
		if arg == "--version" {
			fmt.Println(buildinfo.Version)
			os.Exit(0)
		}
	}

	// 1. Create Fyne app and window.
	a := app.NewWithID("ge.royalhouseofgeorgia.rhg-authenticator")
	appIcon := fyne.NewStaticResource("icon.png", appIconData)
	a.SetIcon(appIcon)
	a.Settings().SetTheme(&rhgTheme{})
	window := a.NewWindow("RHG Authenticator")
	window.Resize(fyne.NewSize(800, 600))

	// 2. Data directory.
	configDir, err := os.UserConfigDir()
	if err != nil {
		fatalDialog(window, fmt.Sprintf("Cannot determine config directory: %v", err), nil, nil, "")
		return
	}
	dataDir := filepath.Join(configDir, "rhg-authenticator")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		fatalDialog(window, fmt.Sprintf("Cannot create data directory: %v", err), nil, nil, "")
		return
	}

	// Debug logging (debug builds only).
	var logger *debuglog.Logger
	if buildinfo.IsDebug() {
		debugLogPath := filepath.Join(dataDir, "debug.log")
		_ = os.Truncate(debugLogPath, 0) // fresh log per session
		logger = debuglog.New(debugLogPath)
		logger.Log("RHG Authenticator starting (debug mode, version: " + buildinfo.Version + ")")
	} else {
		logger = debuglog.New("") // no-op
	}

	// 3. Log path and cleanup.
	logPath := filepath.Join(dataDir, "issuances.json")
	if err := log.CleanStaleTmpFiles(logPath); err != nil {
		fmt.Fprintf(os.Stderr, "warning: log cleanup failed: %v\n", err)
	}

	// 4. Fetch registry (remote only — no cache or embedded fallback).
	reg, err := registry.FetchRegistry(registry.DefaultRegistryURL)
	regOnline := err == nil
	if !regOnline {
		fmt.Fprintf(os.Stderr, "warning: registry fetch failed: %v\n", err)
		reg = core.Registry{}
	}
	logger.Logf("registry fetch: online=%v", regOnline)

	// 5. Build tabs.
	kr := ghapi.NewOSKeyring()
	signContent, signCleanup := gui.NewSignTab(gui.SignTabConfig{
		LogPath: logPath,
		DataDir: dataDir,
		Keyring: kr,
		SafeGo:  func(fn func()) { safeGo(fn, logger, window) },
	}, window)
	regTab := regmgr.NewRegistryTab(window, dataDir)
	historyContent := gui.NewHistoryTab(logPath, registry.DefaultRevocationURL, regTab.ClientForHistory, window)
	lastUpdateCh := make(chan string, 1)
	auditContent := gui.NewAuditTab(window, lastUpdateCh)
	yubiKeyContent := gui.NewYubiKeyTab(reg, regOnline, window)

	signTab := container.NewTabItem("Sign", signContent)
	historyTab := container.NewTabItem("History", historyContent)
	registryTab := container.NewTabItem("Registry", regTab.Content)
	auditTab := container.NewTabItem("Audit", auditContent)
	yubiKeyTab := container.NewTabItem("YubiKey", yubiKeyContent)

	// 6. Set content.
	tabs := container.NewAppTabs(signTab, historyTab, registryTab, auditTab, yubiKeyTab)
	statusBar := gui.NewStatusBar(reg, regOnline, lastUpdateCh)
	updateBanner := container.NewVBox()
	windowContent := container.NewBorder(updateBanner, statusBar, nil, nil, tabs)
	window.SetContent(windowContent)

	// 7. Close intercept for unsaved registry changes + PIN cache cleanup.
	window.SetCloseIntercept(buildCloseHandler(
		regTab.IsDirty,
		buildinfo.IsDebug(),
		logger.Path(),
		signCleanup,
		openFileDefault,
		a.Quit,
		window,
	))

	// 8. Non-blocking registry tab fetch.
	regTab.Fetch()

	// 9. Non-blocking version check.
	safeGo(func() {
		result := update.Check("RoyalHouseOfGeorgia", "rhg_authenticator", buildinfo.Version)
		logger.Logf("version check: update=%v latest=%s", result.UpdateAvailable, result.LatestVersion)
		if result.UpdateAvailable {
			u, err := url.Parse(result.DownloadURL)
			if err != nil || u.Scheme != "https" || u.Host != "github.com" {
				return
			}
			fyne.Do(func() {
				updateBanner.Add(container.NewHBox(
					widget.NewLabel(fmt.Sprintf("Version %s available —", result.LatestVersion)),
					widget.NewHyperlink("Download", u),
				))
			})
		}
	}, logger, window)

	window.ShowAndRun()
}

// fatalDialog shows an error dialog and exits after the user dismisses it.
// If logger is non-nil, the error is logged before the dialog is shown.
// Best-effort issue reporting is attempted; results are shown in the dialog.
func fatalDialog(window fyne.Window, message string, logger *debuglog.Logger, kr ghapi.Keyring, configDir string) {
	logger.Log("FATAL: " + message)

	// Best-effort issue reporting (skip if keyring not yet initialized).
	var reportLine string
	if kr != nil {
		title := errorreport.BuildIssueTitle("internal", message)
		body := errorreport.BuildIssueBody(buildinfo.Version, "internal", message, logger.Path())
		if resultURL, reportErr := errorreport.ReportIssue(context.Background(), kr, configDir, title, body); reportErr == nil && resultURL != "" {
			reportLine = "\n\nError reported: " + resultURL
		}
	}
	if reportLine == "" {
		reportLine = "\n\nPlease report this error at https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/issues"
	}

	d := dialog.NewError(fmt.Errorf("%s%s", message, reportLine), window)
	d.SetOnClosed(func() {
		os.Exit(1)
	})
	d.Show()
	window.ShowAndRun()
}

// showConfirmFunc is the function used to show confirmation dialogs.
// Package-level variable to allow test injection.
var showConfirmFunc = dialog.ShowConfirm

// buildCloseHandler returns a function suitable for SetCloseIntercept that
// handles unsaved-changes confirmation, optional debug log review, cleanup,
// and quit. All dependencies are injected for testability.
func buildCloseHandler(
	isDirty func() bool,
	isDebug bool,
	logPath string,
	cleanup func(),
	openFile func(string),
	quit func(),
	window fyne.Window,
) func() {
	return func() {
		afterDirtyCheck := func() {
			if isDebug && logFileNonEmpty(logPath) {
				showConfirmFunc("Debug Log",
					"Debug log written to debug.log. Review it?",
					func(open bool) {
						if open {
							openFile(logPath)
						}
						cleanup()
						quit()
					}, window)
			} else {
				cleanup()
				quit()
			}
		}

		if isDirty() {
			showConfirmFunc("Unsubmitted Changes",
				"The registry has unsubmitted changes. Exit anyway?",
				func(ok bool) {
					if ok {
						afterDirtyCheck()
					}
				}, window)
		} else {
			afterDirtyCheck()
		}
	}
}

// logFileNonEmpty reports whether the file at path exists and has content.
func logFileNonEmpty(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.Size() > 0
}

// openFileDefault opens a file with the platform's default application.
func openFileDefault(path string) {
	switch runtime.GOOS {
	case "darwin":
		exec.Command("open", path).Start()
	case "windows":
		exec.Command("cmd", "/c", "start", "", path).Start()
	}
}

// safeGo runs fn in a new goroutine with panic recovery. On panic:
// 1. Writes stack trace to stderr (guaranteed by OS).
// 2. Best-effort write to debug.log.
// 3. Shows an error dialog via fyne.Do.
// The goroutine returns after recovery — user is informed instead of staring at a frozen UI.
func safeGo(fn func(), logger *debuglog.Logger, window fyne.Window) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				buf := make([]byte, 4096)
				n := runtime.Stack(buf, false)
				stack := string(buf[:n])
				fmt.Fprintf(os.Stderr, "goroutine panic: %v\n%s\n", r, stack)
				logger.Logf("PANIC (goroutine): %v\n%s", r, stack)
				fyne.Do(func() {
					dialog.ShowError(fmt.Errorf("an internal error occurred — please restart"), window)
				})
			}
		}()
		fn()
	}()
}

// rhgTheme implements fyne.Theme with a Microsoft Office / Fluent UI color scheme.
type rhgTheme struct{}

// Named theme colors to avoid repeating hex values.
var (
	officeBlue    = color.NRGBA{R: 0x2B, G: 0x57, B: 0x9A, A: 0xFF} // #2B579A
	white         = color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF} // #FFFFFF
	fluentNeutral = color.NRGBA{R: 0xF3, G: 0xF2, B: 0xF1, A: 0xFF} // #F3F2F1
)

func (t *rhgTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNamePrimary:
		return officeBlue
	case theme.ColorNameButton:
		return officeBlue
	case theme.ColorNameForegroundOnPrimary:
		return white
	case theme.ColorNameBackground:
		return white
	case theme.ColorNameForeground:
		return color.NRGBA{R: 0x33, G: 0x33, B: 0x33, A: 0xFF} // #333333 body text
	case theme.ColorNameInputBackground:
		return white
	case theme.ColorNameDisabled:
		return color.NRGBA{R: 0x75, G: 0x75, B: 0x75, A: 0xFF} // #757575 WCAG AA
	case theme.ColorNamePlaceHolder:
		return color.NRGBA{R: 0x76, G: 0x76, B: 0x76, A: 0xFF} // #767676 WCAG AA
	case theme.ColorNameHover:
		return color.NRGBA{R: 0x2B, G: 0x57, B: 0x9A, A: 0x26} // ~15% blue overlay
	case theme.ColorNamePressed:
		return color.NRGBA{R: 0x2B, G: 0x57, B: 0x9A, A: 0x33} // ~20% blue overlay
	case theme.ColorNameFocus:
		return color.NRGBA{R: 0x00, G: 0x5A, B: 0x9E, A: 0xFF} // #005A9E distinct focus
	case theme.ColorNameMenuBackground:
		return white
	case theme.ColorNameOverlayBackground:
		return white
	case theme.ColorNameSelection:
		return color.NRGBA{R: 0x2B, G: 0x57, B: 0x9A, A: 0x40} // ~25% blue selection
	case theme.ColorNameDisabledButton:
		return fluentNeutral
	case theme.ColorNameHeaderBackground:
		return fluentNeutral
	case theme.ColorNameInputBorder:
		return color.NRGBA{R: 0x8A, G: 0x88, B: 0x86, A: 0xFF} // #8A8886 Fluent tertiary
	case theme.ColorNameHyperlink:
		return color.NRGBA{R: 0x05, G: 0x63, B: 0xC1, A: 0xFF} // #0563C1 Office link
	case theme.ColorNameScrollBar:
		return color.NRGBA{R: 0xC8, G: 0xC6, B: 0xC4, A: 0xFF} // #C8C6C4 Fluent quaternary
	case theme.ColorNameSeparator:
		return color.NRGBA{R: 0xED, G: 0xEB, B: 0xE9, A: 0xFF} // #EDEBE9 Fluent light
	default:
		return theme.DefaultTheme().Color(name, variant)
	}
}

func (t *rhgTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

func (t *rhgTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (t *rhgTheme) Size(name fyne.ThemeSizeName) float32 {
	return theme.DefaultTheme().Size(name)
}

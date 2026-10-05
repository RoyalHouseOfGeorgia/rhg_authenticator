package main

import (
	"context"
	_ "embed"
	"fmt"
	"image/color"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"

	"github.com/royalhouseofgeorgia/rhg-authenticator/buildinfo"
	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
	"github.com/royalhouseofgeorgia/rhg-authenticator/gui"
	"github.com/royalhouseofgeorgia/rhg-authenticator/log"
	"github.com/royalhouseofgeorgia/rhg-authenticator/registry"
	"github.com/royalhouseofgeorgia/rhg-authenticator/regmgr"
	"github.com/royalhouseofgeorgia/rhg-authenticator/safego"
	"github.com/royalhouseofgeorgia/rhg-authenticator/update"
)

//go:embed icon.png
var appIconData []byte

func main() {
	// Catch panics on the main goroutine. Spawned goroutines use safego.Go.
	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			stack := string(buf[:n])
			// Best-effort write to the diagnostic log via a fresh Logger
			// (synchronous file I/O only; the main logger may not exist yet).
			if configDir, err := os.UserConfigDir(); err == nil {
				debuglog.New(filepath.Join(configDir, "rhg-authenticator", debuglog.FileName)).Logf("PANIC: %v %s", r, stack)
			}
			fmt.Fprintf(os.Stderr, "RHG Authenticator crashed. Please report at https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/issues\n\nPanic: %v\n%s\n", r, stack)
			panic(r) // re-panic so the OS gets the signal
		}
	}()

	// Release CI verifies the signed update zip with the app's own install
	// check; like --version, this must run before any GUI initialization.
	if len(os.Args) > 1 && os.Args[1] == "--verify-update-zip" {
		os.Exit(update.VerifyZipCLI(os.Args[2:], os.Stdout, os.Stderr))
	}

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
		fatalDialog(window, fmt.Sprintf("Cannot determine config directory: %v", err))
		return
	}
	dataDir := filepath.Join(configDir, "rhg-authenticator")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		fatalDialog(window, fmt.Sprintf("Cannot create data directory: %v", err))
		return
	}

	// Diagnostic logging (always on). Prune entries older than the retention
	// window before opening; prune failures go to the log itself, never stderr.
	debugLogPath := filepath.Join(dataDir, debuglog.FileName)
	pruneErr := debuglog.Prune(debugLogPath, debuglog.LogRetention, time.Now())
	logger := debuglog.New(debugLogPath)
	if pruneErr != nil {
		logger.Logf("warning: log prune failed: %v", pruneErr)
	}
	debuglog.CaptureStdlib(logger)
	safego.SetPanicHandler(func(r any, stack []byte) {
		fmt.Fprintf(os.Stderr, "goroutine panic: %v\n%s\n", r, stack)
		logger.Logf("PANIC (goroutine): %v %s", r, stack)
		fyne.Do(func() {
			dialog.ShowError(fmt.Errorf("an internal error occurred — please restart"), window)
		})
	})
	startMsg := "RHG Authenticator starting (version: " + buildinfo.Version + ")"
	if buildinfo.IsDebug() {
		startMsg += " (debug mode)"
	}
	logger.Log(startMsg)

	// 3. Log path and cleanup.
	logPath := filepath.Join(dataDir, "issuances.json")
	if err := log.CleanStaleTmpFiles(logPath); err != nil {
		logger.Logf("warning: log cleanup failed: %s", core.SanitizeForLog(err.Error()))
	}

	// 4. Fetch registry (remote only — no cache or embedded fallback).
	reg, err := registry.FetchRegistry(registry.DefaultRegistryURL)
	regOnline := err == nil
	if !regOnline {
		logger.Logf("warning: registry fetch failed: %s", core.SanitizeForLog(err.Error()))
		reg = core.Registry{}
	}
	logger.Logf("registry fetch: online=%v", regOnline)

	// 5. Build tabs.
	kr := ghapi.NewOSKeyring()
	signContent, signCleanup := gui.NewSignTab(gui.SignTabConfig{
		LogPath: logPath,
		DataDir: dataDir,
		Keyring: kr,
		Logger:  logger,
	}, window)
	regTab := regmgr.NewRegistryTab(window, dataDir)
	historyContent, refreshHistoryLogin := gui.NewHistoryTab(logPath, registry.DefaultRevocationURL, regTab.GitHubClient, regTab.StartLoginOrReconnect, regTab.HandleUnauthorized, window)
	// Push login-state changes (from either tab) into the History tab, then sync
	// once now to reflect the current state. The observer nil-guard makes this
	// correct regardless of whether the async session restore has completed.
	// Safety of this synchronous call: fyne.Do bodies (e.g. the fetchRevocations
	// goroutine's UI mutations) do not run until ShowAndRun starts the driver
	// loop, so this runs strictly before them on the main goroutine — no race.
	// Keep this before ShowAndRun; do not switch fyne.Do to fyne.DoAndWait.
	regTab.SetOnLoginChanged(refreshHistoryLogin)
	refreshHistoryLogin()
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
	window.SetMainMenu(buildMainMenu(func() { gui.OnErrorLogExportTapped(logger.Path(), window) }))

	// 7. Close intercept for unsaved registry changes + PIN cache cleanup.
	window.SetCloseIntercept(buildCloseHandler(
		regTab.IsDirty,
		signCleanup,
		a.Quit,
		window,
	))

	// 8. The registry tab fetches itself once the async login restore finishes,
	// so a logged-in session loads from main via the API (see regmgr.Fetch).

	// 9. Auto-update. "Restart now" reuses the close handler, so unsubmitted
	// registry changes get the same confirm and Cancel never sets relaunch.
	// Fyne 2.8 runs widget callbacks on the main goroutine, so relaunch is
	// written (button tap) and read (after ShowAndRun) on one goroutine.
	var relaunch bool
	restart := buildCloseHandler(
		regTab.IsDirty,
		signCleanup,
		markRelaunchAndQuit(&relaunch, a.Quit),
		window,
	)
	banner := newUpdateBannerView(updateBanner, restart)
	ctx, cancel := context.WithCancel(context.Background())
	manager := update.NewManager(update.Config{
		DataDir: dataDir,
		Running: buildinfo.Version,
		Owner:   "RoyalHouseOfGeorgia",
		Repo:    "rhg_authenticator",
		OnStatus: func(s update.Status) {
			fyne.Do(func() { banner.showStatus(s) })
		},
		OnUpdated: func(version, releaseURL string) {
			fyne.Do(func() { banner.showUpdated(version, releaseURL) })
		},
		Logf: logger.Logf,
	})
	safego.Go(func() { manager.Run(ctx) })

	window.ShowAndRun()

	// The UI has exited: stop checking, then install a Ready update (silently
	// on a normal quit; relaunching after "Restart now").
	cancel()
	manager.ApplyIfReady(relaunch)
}

// fatalDialog shows an error dialog and exits after the user dismisses it.
// It runs before the data directory (and so the error log) exists, so the
// user is asked to report the error manually.
func fatalDialog(window fyne.Window, message string) {
	d := dialog.NewError(fmt.Errorf("%s\n\nPlease report this error at https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/issues", message), window)
	d.SetOnClosed(func() {
		os.Exit(1)
	})
	d.Show()
	window.ShowAndRun()
}

// showConfirmFunc is the function used to show confirmation dialogs.
// Package-level variable to allow test injection.
var showConfirmFunc = dialog.ShowConfirm

// buildMainMenu returns the app menu: an empty File menu (Fyne adds Quit to
// the first menu on Windows, so Help doesn't get it) and Help → Export Error Log….
func buildMainMenu(onExportErrorLog func()) *fyne.MainMenu {
	return fyne.NewMainMenu(
		fyne.NewMenu("File"),
		fyne.NewMenu("Help", fyne.NewMenuItem("Export Error Log…", onExportErrorLog)),
	)
}

// buildCloseHandler returns a function suitable for SetCloseIntercept that
// handles unsaved-changes confirmation, cleanup, and quit. All dependencies
// are injected for testability.
func buildCloseHandler(
	isDirty func() bool,
	cleanup func(),
	quit func(),
	window fyne.Window,
) func() {
	return func() {
		exit := func() {
			cleanup()
			quit()
		}
		if !isDirty() {
			exit()
			return
		}
		showConfirmFunc("Unsubmitted Changes",
			"The registry has unsubmitted changes. Exit anyway?",
			func(ok bool) {
				if ok {
					exit()
				}
			}, window)
	}
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
		// Standard buttons draw their text in ColorNameForeground (#333), so the
		// fill must be light (Fluent secondary style). Primary actions
		// (HighImportance) use ColorNamePrimary with white text.
		return fluentNeutral
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

package main

import (
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/update"
)

const testReleaseURL = "https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/releases/tag/v1.5.1"

// bannerWidgets is every label, hyperlink, and button found in a rendering.
type bannerWidgets struct {
	labels  []*widget.Label
	links   []*widget.Hyperlink
	buttons []*widget.Button
}

func (b bannerWidgets) labelTexts() []string {
	out := make([]string, len(b.labels))
	for i, l := range b.labels {
		out[i] = l.Text
	}
	return out
}

// collectWidgets walks objs (recursing into containers) and gathers widgets.
func collectWidgets(objs []fyne.CanvasObject) bannerWidgets {
	var b bannerWidgets
	var walk func([]fyne.CanvasObject)
	walk = func(objs []fyne.CanvasObject) {
		for _, o := range objs {
			switch w := o.(type) {
			case *fyne.Container:
				walk(w.Objects)
			case *widget.Label:
				b.labels = append(b.labels, w)
			case *widget.Hyperlink:
				b.links = append(b.links, w)
			case *widget.Button:
				b.buttons = append(b.buttons, w)
			}
		}
	}
	walk(objs)
	return b
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestGithubURL(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		ok   bool
	}{
		{"release page", testReleaseURL, true},
		{"github root", "https://github.com/", true},
		{"http scheme", "http://github.com/x", false},
		{"other host", "https://example.com/x", false},
		{"lookalike host", "https://github.com.evil.example/x", false},
		{"subdomain", "https://api.github.com/x", false},
		{"explicit port", "https://github.com:443/x", false},
		{"javascript", "javascript:alert(1)", false},
		{"malformed", "https://github.com/%zz", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, ok := githubURL(tt.raw)
			if ok != tt.ok {
				t.Fatalf("githubURL(%q) ok = %v, want %v", tt.raw, ok, tt.ok)
			}
			if ok && u.String() != tt.raw {
				t.Errorf("githubURL(%q) = %q", tt.raw, u.String())
			}
			if !ok && u != nil {
				t.Errorf("githubURL(%q) returned non-nil URL on rejection", tt.raw)
			}
		})
	}
}

func TestStatusObjects_Idle(t *testing.T) {
	test.NewTempApp(t)
	if objs := statusObjects(update.Status{State: update.StateIdle}, func() {}); len(objs) != 0 {
		t.Errorf("Idle rendered %d objects, want 0", len(objs))
	}
}

func TestStatusObjects_UnknownState(t *testing.T) {
	test.NewTempApp(t)
	if objs := statusObjects(update.Status{State: update.State(99), Version: "1.5.1"}, func() {}); len(objs) != 0 {
		t.Errorf("unknown state rendered %d objects, want 0", len(objs))
	}
}

func TestStatusObjects_Ready(t *testing.T) {
	test.NewTempApp(t)
	restarted := 0
	objs := statusObjects(update.Status{
		State:      update.StateReady,
		Version:    "1.5.1",
		ReleaseURL: testReleaseURL,
	}, func() { restarted++ })
	w := collectWidgets(objs)

	wantLabels := []string{
		"Version 1.5.1 is ready to install.",
		"It will also install the next time you close the app.",
	}
	if got := w.labelTexts(); !equalStrings(got, wantLabels) {
		t.Errorf("labels = %q, want %q", got, wantLabels)
	}
	if !w.labels[0].TextStyle.Bold {
		t.Error("ready title should be bold")
	}
	if len(w.links) != 0 {
		t.Errorf("Ready shows %d links, want 0", len(w.links))
	}
	if len(w.buttons) != 1 {
		t.Fatalf("buttons = %d, want 1", len(w.buttons))
	}
	btn := w.buttons[0]
	if btn.Text != "Restart now" {
		t.Errorf("button text = %q, want %q", btn.Text, "Restart now")
	}
	if btn.Importance != widget.HighImportance {
		t.Errorf("button importance = %v, want HighImportance", btn.Importance)
	}
	test.Tap(btn)
	if restarted != 1 {
		t.Errorf("restart called %d times, want 1", restarted)
	}
}

func TestStatusObjects_ReadyIgnoresReleaseURL(t *testing.T) {
	test.NewTempApp(t)
	objs := statusObjects(update.Status{State: update.StateReady, Version: "1.5.1", ReleaseURL: "http://evil.example"}, func() {})
	if w := collectWidgets(objs); len(w.buttons) != 1 || len(w.labels) != 2 {
		t.Errorf("Ready with bad URL: %d labels, %d buttons; want 2, 1", len(w.labels), len(w.buttons))
	}
}

func TestStatusObjects_ManualOnly(t *testing.T) {
	test.NewTempApp(t)
	objs := statusObjects(update.Status{
		State:      update.StateManualOnly,
		Version:    "1.5.1",
		ReleaseURL: testReleaseURL,
	}, func() { t.Error("restart must not be wired in ManualOnly") })
	w := collectWidgets(objs)

	if got, want := w.labelTexts(), []string{"Version 1.5.1 is available —"}; !equalStrings(got, want) {
		t.Errorf("labels = %q, want %q", got, want)
	}
	if len(w.links) != 1 {
		t.Fatalf("links = %d, want 1", len(w.links))
	}
	if w.links[0].Text != "Download" {
		t.Errorf("link text = %q, want Download", w.links[0].Text)
	}
	if w.links[0].URL.String() != testReleaseURL {
		t.Errorf("link URL = %q, want %q", w.links[0].URL, testReleaseURL)
	}
	if len(w.buttons) != 0 {
		t.Errorf("buttons = %d, want 0", len(w.buttons))
	}
}

func TestStatusObjects_ManualOnlyMoveToApplications(t *testing.T) {
	test.NewTempApp(t)
	objs := statusObjects(update.Status{
		State:              update.StateManualOnly,
		Version:            "1.5.1",
		ReleaseURL:         testReleaseURL,
		MoveToApplications: true,
	}, func() {})
	w := collectWidgets(objs)
	want := []string{
		"Version 1.5.1 is available —",
		"To get updates automatically, move RHG Authenticator into your Applications folder.",
	}
	if got := w.labelTexts(); !equalStrings(got, want) {
		t.Errorf("labels = %q, want %q", got, want)
	}
	if len(w.links) != 1 || w.links[0].Text != "Download" {
		t.Errorf("want one Download link, got %d links", len(w.links))
	}
}

func TestStatusObjects_ManualOnlyInvalidURLShowsNothing(t *testing.T) {
	test.NewTempApp(t)
	for _, raw := range []string{"", "http://github.com/x", "https://evil.example/x"} {
		for _, move := range []bool{false, true} {
			objs := statusObjects(update.Status{
				State:              update.StateManualOnly,
				Version:            "1.5.1",
				ReleaseURL:         raw,
				MoveToApplications: move,
			}, func() {})
			if len(objs) != 0 {
				t.Errorf("ManualOnly url=%q move=%v rendered %d objects, want 0", raw, move, len(objs))
			}
		}
	}
}

func TestUpdatedObjects(t *testing.T) {
	test.NewTempApp(t)
	closed := 0
	w := collectWidgets(updatedObjects("1.5.1", testReleaseURL, func() { closed++ }))

	if got, want := w.labelTexts(), []string{"Updated to version 1.5.1."}; !equalStrings(got, want) {
		t.Errorf("labels = %q, want %q", got, want)
	}
	if !w.labels[0].TextStyle.Bold {
		t.Error("updated label should be bold")
	}
	if len(w.links) != 1 || w.links[0].Text != "What's new" || w.links[0].URL.String() != testReleaseURL {
		t.Fatalf("want one What's new link to %s, got %+v", testReleaseURL, w.links)
	}
	if len(w.buttons) != 1 {
		t.Fatalf("buttons = %d, want 1 (close)", len(w.buttons))
	}
	btn := w.buttons[0]
	if btn.Text != "" || btn.Icon != theme.CancelIcon() {
		t.Errorf("close button text=%q icon=%v; want empty text and CancelIcon", btn.Text, btn.Icon)
	}
	if btn.Importance != widget.LowImportance {
		t.Errorf("close button importance = %v, want LowImportance", btn.Importance)
	}
	test.Tap(btn)
	if closed != 1 {
		t.Errorf("onClose called %d times, want 1", closed)
	}
}

func TestUpdatedObjects_InvalidURLOmitsLink(t *testing.T) {
	test.NewTempApp(t)
	for _, raw := range []string{"", "http://github.com/x", "https://evil.example/x", "::bad"} {
		w := collectWidgets(updatedObjects("1.5.1", raw, func() {}))
		if got, want := w.labelTexts(), []string{"Updated to version 1.5.1."}; !equalStrings(got, want) {
			t.Errorf("url=%q labels = %q, want %q", raw, got, want)
		}
		if len(w.links) != 0 {
			t.Errorf("url=%q: %d links, want 0", raw, len(w.links))
		}
		if len(w.buttons) != 1 {
			t.Errorf("url=%q: %d buttons, want 1 (close)", raw, len(w.buttons))
		}
	}
}

func TestNewUpdateBannerView_SlotsStartHidden(t *testing.T) {
	test.NewTempApp(t)
	parent := container.NewVBox()
	v := newUpdateBannerView(parent, func() {})
	if len(parent.Objects) != 2 {
		t.Fatalf("parent has %d children, want 2 slots", len(parent.Objects))
	}
	if parent.Objects[0] != v.updated || parent.Objects[1] != v.status {
		t.Error("slots not added to parent in order (updated, status)")
	}
	if v.status.Visible() || v.updated.Visible() {
		t.Error("empty slots should be hidden")
	}
	if got := parent.MinSize().Height; got != 0 {
		t.Errorf("empty banner height = %v, want 0", got)
	}
}

func TestUpdateBannerView_ShowStatusIsIdempotentAndReplaces(t *testing.T) {
	test.NewTempApp(t)
	restarted := 0
	v := newUpdateBannerView(container.NewVBox(), func() { restarted++ })
	ready := update.Status{State: update.StateReady, Version: "1.5.1", ReleaseURL: testReleaseURL}

	v.showStatus(ready)
	v.showStatus(ready)
	if !v.status.Visible() {
		t.Error("status slot hidden while Ready")
	}
	w := collectWidgets(v.status.Objects)
	if len(w.buttons) != 1 || len(w.labels) != 2 {
		t.Fatalf("after two Ready renders: %d labels, %d buttons; want 2, 1", len(w.labels), len(w.buttons))
	}
	test.Tap(w.buttons[0])
	if restarted != 1 {
		t.Errorf("restart called %d times, want 1", restarted)
	}

	v.showStatus(update.Status{State: update.StateManualOnly, Version: "1.5.2", ReleaseURL: testReleaseURL})
	w = collectWidgets(v.status.Objects)
	if got, want := w.labelTexts(), []string{"Version 1.5.2 is available —"}; !equalStrings(got, want) {
		t.Errorf("after ManualOnly labels = %q, want %q", got, want)
	}
	if len(w.buttons) != 0 {
		t.Error("Restart now button left over after ManualOnly")
	}

	v.showStatus(update.Status{State: update.StateIdle})
	if len(v.status.Objects) != 0 || v.status.Visible() {
		t.Errorf("Idle: %d objects, visible=%v; want 0, false", len(v.status.Objects), v.status.Visible())
	}
}

func TestUpdateBannerView_UpdatedIndependentOfStatus(t *testing.T) {
	test.NewTempApp(t)
	v := newUpdateBannerView(container.NewVBox(), func() {})

	v.showUpdated("1.5.1", testReleaseURL)
	v.showUpdated("1.5.1", testReleaseURL)
	if !v.updated.Visible() {
		t.Fatal("updated slot hidden after showUpdated")
	}
	w := collectWidgets(v.updated.Objects)
	if len(w.labels) != 1 || len(w.links) != 1 || len(w.buttons) != 1 {
		t.Fatalf("after two renders: %d labels, %d links, %d buttons; want 1 each",
			len(w.labels), len(w.links), len(w.buttons))
	}

	// A status change must not disturb the "Updated to" notice.
	v.showStatus(update.Status{State: update.StateReady, Version: "1.5.2"})
	v.showStatus(update.Status{State: update.StateIdle})
	if len(v.updated.Objects) == 0 {
		t.Error("status change cleared the Updated notice")
	}

	// × dismisses only the notice.
	v.showStatus(update.Status{State: update.StateManualOnly, Version: "1.5.2", ReleaseURL: testReleaseURL})
	test.Tap(w.buttons[0])
	if len(v.updated.Objects) != 0 || v.updated.Visible() {
		t.Errorf("after ×: %d objects, visible=%v; want 0, false", len(v.updated.Objects), v.updated.Visible())
	}
	if len(v.status.Objects) == 0 || !v.status.Visible() {
		t.Error("× also cleared the status slot")
	}
}

func TestMarkRelaunchAndQuit(t *testing.T) {
	var relaunch bool
	quits := 0
	markRelaunchAndQuit(&relaunch, func() {
		if !relaunch {
			t.Error("relaunch must be set before quit runs")
		}
		quits++
	})()
	if !relaunch || quits != 1 {
		t.Errorf("relaunch=%v quits=%d; want true, 1", relaunch, quits)
	}
}

// restartHandler builds "Restart now" exactly as main does: the close handler
// with markRelaunchAndQuit as its quit.
func restartHandler(dirty bool, relaunch *bool, cleaned, quits *int) func() {
	return buildCloseHandler(
		func() bool { return dirty },
		func() { *cleaned++ },
		markRelaunchAndQuit(relaunch, func() { *quits++ }),
		nil,
	)
}

func TestRestartNow_Clean(t *testing.T) {
	stubShowConfirm(t, func(title, msg string, cb func(bool), w fyne.Window) {
		t.Errorf("unexpected dialog %q", title)
	})
	var relaunch bool
	var cleaned, quits int
	restartHandler(false, &relaunch, &cleaned, &quits)()
	if !relaunch || cleaned != 1 || quits != 1 {
		t.Errorf("relaunch=%v cleaned=%d quits=%d; want true, 1, 1", relaunch, cleaned, quits)
	}
}

func TestRestartNow_DirtyConfirmed(t *testing.T) {
	var titles []string
	stubShowConfirm(t, func(title, msg string, cb func(bool), w fyne.Window) {
		titles = append(titles, title)
		cb(true)
	})
	var relaunch bool
	var cleaned, quits int
	restartHandler(true, &relaunch, &cleaned, &quits)()
	if len(titles) != 1 || titles[0] != "Unsubmitted Changes" {
		t.Errorf("dialogs = %v, want [Unsubmitted Changes]", titles)
	}
	if !relaunch || cleaned != 1 || quits != 1 {
		t.Errorf("relaunch=%v cleaned=%d quits=%d; want true, 1, 1", relaunch, cleaned, quits)
	}
}

func TestRestartNow_DirtyCancelled_KeepsAppAndBanner(t *testing.T) {
	test.NewTempApp(t)
	var titles []string
	stubShowConfirm(t, func(title, msg string, cb func(bool), w fyne.Window) {
		titles = append(titles, title)
		cb(false)
	})
	var relaunch bool
	var cleaned, quits int
	v := newUpdateBannerView(container.NewVBox(), restartHandler(true, &relaunch, &cleaned, &quits))
	v.showStatus(update.Status{State: update.StateReady, Version: "1.5.1"})

	w := collectWidgets(v.status.Objects)
	if len(w.buttons) != 1 {
		t.Fatalf("buttons = %d, want 1", len(w.buttons))
	}
	test.Tap(w.buttons[0])

	if len(titles) != 1 || titles[0] != "Unsubmitted Changes" {
		t.Errorf("dialogs = %v, want [Unsubmitted Changes]", titles)
	}
	if relaunch {
		t.Error("relaunch set although the user cancelled")
	}
	if cleaned != 0 || quits != 0 {
		t.Errorf("cleaned=%d quits=%d; want 0, 0 (app stays open)", cleaned, quits)
	}
	if !v.status.Visible() || len(collectWidgets(v.status.Objects).buttons) != 1 {
		t.Error("Ready banner should remain after cancel")
	}
}

package service

import "testing"

// --- ResolveLoginState tests ---

func TestResolveLoginState_Online(t *testing.T) {
	loggedIn, offline, text := ResolveLoginState(false, "myuser", false)
	if !loggedIn {
		t.Error("loggedIn = false, want true")
	}
	if offline {
		t.Error("offline = true, want false")
	}
	if text != "Logged in as @myuser" {
		t.Errorf("statusText = %q, want %q", text, "Logged in as @myuser")
	}
}

func TestResolveLoginState_Unauthorized(t *testing.T) {
	loggedIn, offline, text := ResolveLoginState(true, "", true)
	if loggedIn {
		t.Error("loggedIn = true, want false")
	}
	if offline {
		t.Error("offline = true, want false")
	}
	if text != "Not logged in" {
		t.Errorf("statusText = %q, want %q", text, "Not logged in")
	}
}

func TestResolveLoginState_Offline(t *testing.T) {
	loggedIn, offline, text := ResolveLoginState(false, "", true)
	if !loggedIn {
		t.Error("loggedIn = false, want true")
	}
	if !offline {
		t.Error("offline = false, want true")
	}
	if text != "GitHub unreachable" {
		t.Errorf("statusText = %q, want %q", text, "GitHub unreachable")
	}
}

func TestResolveLoginState_EmptyUsername(t *testing.T) {
	// No error but empty username — still logged in, just no name to display.
	loggedIn, offline, text := ResolveLoginState(false, "", false)
	if !loggedIn {
		t.Error("loggedIn = false, want true")
	}
	if offline {
		t.Error("offline = true, want false")
	}
	if text != "Logged in as @" {
		t.Errorf("statusText = %q, want %q", text, "Logged in as @")
	}
}

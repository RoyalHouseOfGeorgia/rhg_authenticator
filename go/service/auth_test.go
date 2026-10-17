package service

import "testing"

func TestAuthState_StatusText(t *testing.T) {
	for _, tc := range []struct {
		st   AuthState
		want string
	}{
		{AuthState{LoggedIn: true, User: "myuser"}, "Logged in as @myuser"},
		{AuthState{}, "Not logged in"},
		{AuthState{LoggedIn: true, Offline: true}, "GitHub unreachable"},
		{AuthState{LoggedIn: true}, "Logged in as @"},
	} {
		if got := tc.st.StatusText(); got != tc.want {
			t.Errorf("%+v.StatusText() = %q, want %q", tc.st, got, tc.want)
		}
	}
}

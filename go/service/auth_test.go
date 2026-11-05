package service

import (
	"encoding/json"
	"testing"
)

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

func TestAuthState_MarshalJSON(t *testing.T) {
	data, err := json.Marshal(AuthState{LoggedIn: true, User: "myuser"})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"loggedIn":true,"offline":false,"user":"myuser","statusText":"Logged in as @myuser"}`
	if string(data) != want {
		t.Errorf("Marshal = %s, want %s", data, want)
	}
	// Nested and through a pointer it encodes the same way.
	data, err = json.Marshal(struct{ S *AuthState }{&AuthState{}})
	if err != nil {
		t.Fatal(err)
	}
	inner := `{"loggedIn":false,"offline":false,"user":"","statusText":"Not logged in"}`
	if want := `{"S":` + inner + `}`; string(data) != want {
		t.Errorf("nested Marshal = %s, want %s", data, want)
	}
	// The extra field is ignored on decode.
	var back AuthState
	if err := json.Unmarshal([]byte(inner), &back); err != nil || back != (AuthState{}) {
		t.Errorf("Unmarshal = %+v, %v", back, err)
	}
}

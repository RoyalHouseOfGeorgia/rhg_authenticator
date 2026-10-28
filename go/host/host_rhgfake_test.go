//go:build rhgfake

package host

import (
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
)

// TestNewService_FakeBuildDropsKeyring: whatever keyring a front end passes,
// the test build's service has none, so it can't restore or start a GitHub
// session.
func TestNewService_FakeBuildDropsKeyring(t *testing.T) {
	prev := newService
	t.Cleanup(func() { newService = prev })
	var got service.Config
	newService = func(cfg service.Config) (*service.App, error) {
		got = cfg
		return &service.App{}, nil
	}
	if _, err := NewService(service.Config{Keyring: ghapi.NewFakeKeyring()}); err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if got.Keyring != nil {
		t.Errorf("Keyring = %T, want none", got.Keyring)
	}
}

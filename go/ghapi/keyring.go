package ghapi

import (
	"errors"
	"sync"

	"github.com/zalando/go-keyring"
)

// ErrKeyNotFound is returned when a key is not present in the keyring.
var ErrKeyNotFound = errors.New("keyring: key not found")

// Keyring abstracts OS credential storage for testability.
type Keyring interface {
	Get(service, key string) (string, error)
	Set(service, key, value string) error
	Delete(service, key string) error
}

// osKeyring is the production implementation wrapping github.com/zalando/go-keyring.
type osKeyring struct{}

// NewOSKeyring returns a Keyring backed by the OS credential store.
func NewOSKeyring() Keyring {
	return osKeyring{}
}

func (osKeyring) Get(service, key string) (string, error) {
	val, err := keyring.Get(service, key)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", ErrKeyNotFound
	}
	return val, err
}

func (osKeyring) Set(service, key, value string) error {
	return keyring.Set(service, key, value)
}

func (osKeyring) Delete(service, key string) error {
	err := keyring.Delete(service, key)
	if errors.Is(err, keyring.ErrNotFound) {
		return ErrKeyNotFound
	}
	return err
}

// FakeKeyring is an in-memory Keyring implementation for tests.
// All operations are thread-safe. Set SimulateError to a non-nil value
// to make all operations return that error.
type FakeKeyring struct {
	mu            sync.Mutex
	store         map[string]string
	SimulateError error
}

// NewFakeKeyring returns a ready-to-use FakeKeyring.
func NewFakeKeyring() *FakeKeyring {
	return &FakeKeyring{store: make(map[string]string)}
}

func compoundKey(service, key string) string {
	return service + "\x00" + key
}

func (f *FakeKeyring) Get(service, key string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.SimulateError != nil {
		return "", f.SimulateError
	}
	val, ok := f.store[compoundKey(service, key)]
	if !ok {
		return "", ErrKeyNotFound
	}
	return val, nil
}

func (f *FakeKeyring) Set(service, key, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.SimulateError != nil {
		return f.SimulateError
	}
	f.store[compoundKey(service, key)] = value
	return nil
}

func (f *FakeKeyring) Delete(service, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.SimulateError != nil {
		return f.SimulateError
	}
	ck := compoundKey(service, key)
	if _, ok := f.store[ck]; !ok {
		return ErrKeyNotFound
	}
	delete(f.store, ck)
	return nil
}

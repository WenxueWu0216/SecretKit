package cli

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/WenxueWu0216/SecretKit/sdk/go/secretkit"
	"github.com/zalando/go-keyring"
)

const keyringService = "secretkit"

var (
	errNotLoggedIn = errors.New("not logged in; run `secretkit login` or set SECRETKIT_TOKEN")
	// ErrKeychainUnavailable is returned when the OS keychain cannot be used.
	// Tokens are never written to a file as a fallback.
	ErrKeychainUnavailable = errors.New("no OS keychain available; tokens are only stored in the OS keychain. " +
		"On Linux this needs a Secret Service provider such as gnome-keyring. " +
		"Alternatively set SECRETKIT_TOKEN to an access token")
)

// TokenStore persists login tokens per server URL.
type TokenStore interface {
	Load(server string) (secretkit.Token, error)
	Save(server string, tok secretkit.Token) error
	Delete(server string) error
}

// KeyringStore stores tokens in the OS keychain via go-keyring.
type KeyringStore struct{}

func (KeyringStore) Load(server string) (secretkit.Token, error) {
	raw, err := keyring.Get(keyringService, server)
	if err != nil {
		return secretkit.Token{}, keychainErr(err)
	}
	var tok secretkit.Token
	if err := json.Unmarshal([]byte(raw), &tok); err != nil {
		return secretkit.Token{}, fmt.Errorf("keychain entry for %s is corrupt; run `secretkit logout` then log in again", server)
	}
	return tok, nil
}

func (KeyringStore) Save(server string, tok secretkit.Token) error {
	raw, err := json.Marshal(tok)
	if err != nil {
		return err
	}
	return keychainErr(keyring.Set(keyringService, server, string(raw)))
}

func (KeyringStore) Delete(server string) error {
	return keychainErr(keyring.Delete(keyringService, server))
}

func keychainErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, keyring.ErrNotFound):
		return errNotLoggedIn
	}
	// go-keyring does not export a distinct error for a missing backend
	// (e.g. no D-Bus session), so any other failure is reported as such.
	return fmt.Errorf("%w (%w)", ErrKeychainUnavailable, err)
}

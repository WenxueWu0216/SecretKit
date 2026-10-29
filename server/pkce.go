package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
)

// PKCE verifier constraints from RFC 7636 section 4.1.
const (
	minVerifierLen = 43
	maxVerifierLen = 128
)

var errInvalidVerifier = errors.New("code_verifier must be 43-128 characters of [A-Za-z0-9-._~]")

// S256Challenge returns BASE64URL(SHA256(verifier)) without padding.
func S256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func validateVerifier(verifier string) error {
	if len(verifier) < minVerifierLen || len(verifier) > maxVerifierLen {
		return errInvalidVerifier
	}
	for i := 0; i < len(verifier); i++ {
		c := verifier[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-', c == '.', c == '_', c == '~':
		default:
			return errInvalidVerifier
		}
	}
	return nil
}

func validChallenge(challenge string) bool {
	// A SHA-256 digest is always 43 characters in unpadded base64url.
	if len(challenge) != 43 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(challenge)
	return err == nil
}

func verifyPKCE(challenge, verifier string) bool {
	if validateVerifier(verifier) != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(S256Challenge(verifier)), []byte(challenge)) == 1
}

package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

func randomToken(nbytes int) string {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// hashToken keys stored credentials by digest so a dump of server memory
// does not hand out usable tokens.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// userCodeAlphabet omits vowels and look-alike characters (RFC 8628 section 6.1).
const userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

func randomUserCode() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	out := make([]byte, 0, 9)
	for i, v := range b {
		if i == 4 {
			out = append(out, '-')
		}
		// 256 is not a multiple of 20, so this has a slight bias; acceptable
		// because user codes are short-lived and rate limited by expiry.
		out = append(out, userCodeAlphabet[int(v)%len(userCodeAlphabet)])
	}
	return string(out)
}

func normalizeUserCode(code string) string {
	out := make([]byte, 0, len(code))
	for i := 0; i < len(code); i++ {
		c := code[i]
		switch {
		case c >= 'a' && c <= 'z':
			out = append(out, c-'a'+'A')
		case c >= 'A' && c <= 'Z':
			out = append(out, c)
		}
	}
	if len(out) != 8 {
		return string(out)
	}
	return string(out[:4]) + "-" + string(out[4:])
}

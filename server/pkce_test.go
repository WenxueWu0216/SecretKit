package server

import (
	"strings"
	"testing"
)

func TestS256ChallengeRFC7636Vector(t *testing.T) {
	// Appendix B of RFC 7636.
	got := S256Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
	if want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"; got != want {
		t.Fatalf("S256Challenge = %q, want %q", got, want)
	}
}

func TestVerifyPKCE(t *testing.T) {
	verifier := strings.Repeat("a", 43)
	challenge := S256Challenge(verifier)
	tests := []struct {
		name      string
		challenge string
		verifier  string
		want      bool
	}{
		{"match", challenge, verifier, true},
		{"wrong verifier", challenge, strings.Repeat("b", 43), false},
		{"too short", S256Challenge("short"), "short", false},
		{"too long", S256Challenge(strings.Repeat("a", 129)), strings.Repeat("a", 129), false},
		{"illegal character", S256Challenge(strings.Repeat("a", 42) + "!"), strings.Repeat("a", 42) + "!", false},
		{"max length", S256Challenge(strings.Repeat("~", 128)), strings.Repeat("~", 128), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := verifyPKCE(tt.challenge, tt.verifier); got != tt.want {
				t.Fatalf("verifyPKCE = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidChallenge(t *testing.T) {
	if !validChallenge(S256Challenge(strings.Repeat("x", 50))) {
		t.Fatal("real challenge rejected")
	}
	for _, bad := range []string{"", "plain-verifier", strings.Repeat("=", 43)} {
		if validChallenge(bad) {
			t.Errorf("validChallenge(%q) = true", bad)
		}
	}
}

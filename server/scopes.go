package server

import (
	"slices"
	"strings"
)

// Supported scopes.
const (
	ScopeRead  = "secrets:read"
	ScopeWrite = "secrets:write"
)

func parseScopes(raw string) ([]string, error) {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return []string{ScopeRead}, nil
	}
	var scopes []string
	for _, s := range fields {
		if s != ScopeRead && s != ScopeWrite {
			return nil, oauthErr(CodeInvalidScope, "unknown scope "+s)
		}
		if !slices.Contains(scopes, s) {
			scopes = append(scopes, s)
		}
	}
	slices.Sort(scopes)
	return scopes, nil
}

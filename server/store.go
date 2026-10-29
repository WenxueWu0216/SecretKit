package server

import (
	"regexp"
	"sort"
	"sync"
	"time"
)

// MaxSecretSize matches maxLength of PutSecretRequest.value in the spec.
const MaxSecretSize = 64 * 1024

var secretNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// ValidSecretName reports whether name is usable as an environment variable.
func ValidSecretName(name string) bool { return secretNameRE.MatchString(name) }

type SecretMetadata struct {
	Name      string    `json:"name"`
	Version   int64     `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Secret struct {
	SecretMetadata
	Value string `json:"value"`
}

// SecretStore is an in-memory, process-lifetime secret store.
type SecretStore struct {
	mu      sync.RWMutex
	now     func() time.Time
	secrets map[string]Secret
}

func NewSecretStore(now func() time.Time) *SecretStore {
	return &SecretStore{now: now, secrets: make(map[string]Secret)}
}

func (s *SecretStore) Get(name string) (Secret, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sec, ok := s.secrets[name]
	return sec, ok
}

func (s *SecretStore) Put(name, value string) SecretMetadata {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec := s.secrets[name]
	sec.Name = name
	sec.Value = value
	sec.Version++
	sec.UpdatedAt = s.now().UTC()
	s.secrets[name] = sec
	return sec.SecretMetadata
}

func (s *SecretStore) List() []SecretMetadata {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]SecretMetadata, 0, len(s.secrets))
	for _, sec := range s.secrets {
		out = append(out, sec.SecretMetadata)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

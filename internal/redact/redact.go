// Package redact replaces known secret values in output streams.
package redact

import (
	"bytes"
	"io"
	"slices"
	"sync"
)

// Marker replaces every occurrence of a secret value.
const Marker = "[REDACTED]"

// MinLength is the shortest value that is redacted. Shorter values such as
// "1" or "true" would mangle unrelated output, so they are left alone; the
// design doc lists this as an accepted gap.
const MinLength = 4

// Set is a concurrency-safe collection of secret values shared by writers.
type Set struct {
	mu      sync.RWMutex
	secrets [][]byte // longest first, so overlapping secrets redact fully
	first   [256]bool
	maxLen  int
}

// NewSet returns a Set containing values.
func NewSet(values ...string) *Set {
	s := &Set{}
	for _, v := range values {
		s.Add(v)
	}
	return s
}

// Add registers a value. Values shorter than MinLength are ignored.
func (s *Set) Add(value string) {
	if len(value) < MinLength {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.secrets {
		if string(existing) == value {
			return
		}
	}
	s.secrets = append(s.secrets, []byte(value))
	slices.SortFunc(s.secrets, func(a, b []byte) int { return len(b) - len(a) })
	s.first[value[0]] = true
	s.maxLen = max(s.maxLen, len(value))
}

// String redacts a complete string.
func (s *Set) String(in string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out, _ := s.redactLocked(nil, []byte(in), true)
	return string(out)
}

// redactLocked appends the redacted form of buf to dst. Unless final, it
// stops at the first position where buf's tail could still grow into a
// secret, and returns that tail as rest so the caller can hold it back.
func (s *Set) redactLocked(dst, buf []byte, final bool) (out, rest []byte) {
	i := 0
	for i < len(buf) {
		if !s.first[buf[i]] {
			// Fast path: copy the run of bytes that cannot start a secret.
			j := i + 1
			for j < len(buf) && !s.first[buf[j]] {
				j++
			}
			dst = append(dst, buf[i:j]...)
			i = j
			continue
		}
		tail := buf[i:]
		if !final && len(tail) < s.maxLen && s.couldGrowIntoSecretLocked(tail) {
			// Hold back before checking full matches: a shorter secret may
			// match now while a longer one would match with more input.
			return dst, tail
		}
		if n := s.matchLocked(tail); n > 0 {
			dst = append(dst, Marker...)
			i += n
			continue
		}
		dst = append(dst, buf[i])
		i++
	}
	return dst, nil
}

func (s *Set) couldGrowIntoSecretLocked(tail []byte) bool {
	for _, sec := range s.secrets {
		if len(sec) > len(tail) && bytes.HasPrefix(sec, tail) {
			return true
		}
	}
	return false
}

func (s *Set) matchLocked(tail []byte) int {
	for _, sec := range s.secrets {
		if bytes.HasPrefix(tail, sec) {
			return len(sec)
		}
	}
	return 0
}

// Writer redacts secrets in a byte stream, including secrets split across
// Write calls. It holds back at most one secret's length of output until it
// can tell whether a secret is being written, so callers must call Flush
// (or Close) at the end of the stream.
type Writer struct {
	mu      sync.Mutex
	dst     io.Writer
	set     *Set
	pending []byte
	scratch []byte
}

// NewWriter returns a Writer that writes redacted output to dst.
func NewWriter(dst io.Writer, set *Set) *Writer {
	return &Writer{dst: dst, set: set}
}

// Write always reports len(p) on success because held-back bytes are
// written later; the caller's bytes are accepted, not lost.
func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pending = append(w.pending, p...)
	if err := w.emit(false); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Flush writes any held-back bytes. Call it when the stream ends.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.emit(true)
}

// Close flushes the writer. It does not close the destination.
func (w *Writer) Close() error { return w.Flush() }

func (w *Writer) emit(final bool) error {
	w.set.mu.RLock()
	out, rest := w.set.redactLocked(w.scratch[:0], w.pending, final)
	w.set.mu.RUnlock()
	w.scratch = out
	// rest aliases pending, so move it to the front before reusing pending.
	w.pending = append(w.pending[:0], rest...)
	if len(out) == 0 {
		return nil
	}
	_, err := w.dst.Write(out)
	return err
}

package redact

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

func TestStringRedaction(t *testing.T) {
	set := NewSet("fake-token-123", "hunter2-fake", "ab")
	tests := []struct{ in, want string }{
		{"no secrets here", "no secrets here"},
		{"token=fake-token-123", "token=[REDACTED]"},
		{"fake-token-123fake-token-123", "[REDACTED][REDACTED]"},
		{"a hunter2-fake b fake-token-123 c", "a [REDACTED] b [REDACTED] c"},
		{"short ab stays", "short ab stays"},
		{"fake-token-12", "fake-token-12"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := set.String(tt.in); got != tt.want {
			t.Errorf("String(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestOverlappingSecretsPreferLongest(t *testing.T) {
	set := NewSet("pass", "password-fake")
	if got := set.String("password-fake pass"); got != "[REDACTED] [REDACTED]" {
		t.Fatalf("got %q", got)
	}
}

func writeChunks(t *testing.T, set *Set, chunks []string) string {
	t.Helper()
	var out bytes.Buffer
	w := NewWriter(&out, set)
	for _, c := range chunks {
		n, err := w.Write([]byte(c))
		if err != nil || n != len(c) {
			t.Fatalf("Write(%q) = %d, %v", c, n, err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestWriterSecretSplitAcrossChunks(t *testing.T) {
	set := NewSet("fake-token-123")
	tests := [][]string{
		{"token=fake-", "token-123\n"},
		{"token=f", "a", "k", "e", "-token-12", "3", "\n"},
		{"fake-token-12", "3fake-token-123"},
		{"", "fake-token-123", ""},
	}
	for _, chunks := range tests {
		got := writeChunks(t, set, chunks)
		if strings.Contains(got, "fake-token-123") || !strings.Contains(got, Marker) {
			t.Errorf("chunks %q -> %q", chunks, got)
		}
	}
}

func TestWriterEveryByteSplit(t *testing.T) {
	set := NewSet("s3cr3t-fake-value", "another-fake")
	input := "pre s3cr3t-fake-value mid another-fake s3cr3t-fake-valu end another-fakeanother-fake"
	want := set.String(input)
	// Split the input at every pair of positions to cover all chunk boundaries.
	for i := 0; i <= len(input); i++ {
		for j := i; j <= len(input); j++ {
			got := writeChunks(t, set, []string{input[:i], input[i:j], input[j:]})
			if got != want {
				t.Fatalf("split at %d,%d: got %q, want %q", i, j, got, want)
			}
		}
	}
}

func TestWriterPartialPrefixIsFlushed(t *testing.T) {
	set := NewSet("fake-token-123")
	var out bytes.Buffer
	w := NewWriter(&out, set)
	_, _ = w.Write([]byte("value: fake-tok"))
	if out.String() != "value: " {
		t.Fatalf("before flush: %q", out.String())
	}
	_ = w.Flush()
	if out.String() != "value: fake-tok" {
		t.Fatalf("after flush: %q", out.String())
	}
}

func TestWriterLongerSecretWinsAcrossChunks(t *testing.T) {
	// "abcd" fully matches at the first chunk boundary, but more input turns
	// it into the longer secret; neither must leak.
	set := NewSet("abcd", "abcdefgh")
	if got := writeChunks(t, set, []string{"x abcd", "efgh y"}); got != "x [REDACTED] y" {
		t.Fatalf("got %q", got)
	}
}

func TestWriterSecretAddedMidStream(t *testing.T) {
	set := NewSet()
	var out bytes.Buffer
	w := NewWriter(&out, set)
	_, _ = w.Write([]byte("before fake-late-secret\n"))
	set.Add("fake-late-secret")
	_, _ = w.Write([]byte("after fake-late-secret\n"))
	_ = w.Flush()
	if got := out.String(); got != "before fake-late-secret\nafter [REDACTED]\n" {
		t.Fatalf("got %q", got)
	}
}

func TestWriterConcurrentWrites(t *testing.T) {
	set := NewSet("fake-concurrent-secret")
	var out bytes.Buffer
	w := NewWriter(&out, set)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				_, _ = w.Write([]byte("line fake-concurrent-secret\n"))
			}
		}()
	}
	wg.Wait()
	_ = w.Flush()
	if strings.Contains(out.String(), "fake-concurrent-secret") {
		t.Fatal("secret leaked under concurrent writes")
	}
	if got := strings.Count(out.String(), Marker); got != 800 {
		t.Fatalf("redactions = %d, want 800", got)
	}
}

func BenchmarkWriter(b *testing.B) {
	set := NewSet("fake-bench-secret-value", "another-fake-bench-secret")
	line := []byte(strings.Repeat("ordinary log output without secrets ", 20) + "fake-bench-secret-value\n")
	w := NewWriter(discard{}, set)
	b.SetBytes(int64(len(line)))
	b.ResetTimer()
	for range b.N {
		_, _ = w.Write(line)
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// Package bench measures CLI cold start and SDK request latency against
// the in-memory mock server over loopback TCP.
package bench

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/WenxueWu0216/SecretKit/sdk/go/secretkit"
	"github.com/WenxueWu0216/SecretKit/server"
)

const benchToken = "fake-bench-token"

var cliBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "secretkit-bench")
	if err != nil {
		panic(err)
	}
	cliBin = filepath.Join(dir, "secretkit")
	// Built the way a release is (stripped, no debug info) so cold start
	// reflects what users run.
	build := exec.Command("go", "build", "-trimpath", "-ldflags", "-s -w", "-o", cliBin, "../cmd/secretkit")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func startServer(b *testing.B, nSecrets int) string {
	b.Helper()
	srv := server.New(server.Config{})
	srv.Tokens.AddStaticToken(benchToken, []string{server.ScopeRead, server.ScopeWrite})
	for i := range nSecrets {
		srv.Secrets.Put(fmt.Sprintf("SECRET_%03d", i), "fake-value-for-benchmarks")
	}
	ts := httptest.NewServer(srv)
	b.Cleanup(ts.Close)
	return ts.URL
}

// reportPercentiles adds p50/p99 latency metrics next to the mean ns/op.
func reportPercentiles(b *testing.B, samples []time.Duration) {
	if len(samples) == 0 {
		return
	}
	slices.Sort(samples)
	pct := func(p float64) float64 {
		return float64(samples[int(float64(len(samples)-1)*p)].Microseconds())
	}
	b.ReportMetric(pct(0.50), "p50-µs")
	b.ReportMetric(pct(0.99), "p99-µs")
}

func BenchmarkCLIColdStart(b *testing.B) {
	url := startServer(b, 10)
	cases := []struct {
		name string
		args []string
	}{
		{"version", []string{"--version"}},
		{"get", []string{"get", "SECRET_001"}},
		{"run-true", []string{"run", "--", "true"}},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			samples := make([]time.Duration, 0, b.N)
			for b.Loop() {
				cmd := exec.Command(cliBin, tc.args...)
				cmd.Env = append(os.Environ(), "SECRETKIT_SERVER="+url, "SECRETKIT_TOKEN="+benchToken)
				start := time.Now()
				if out, err := cmd.CombinedOutput(); err != nil {
					b.Fatalf("%v: %v\n%s", tc.args, err, out)
				}
				samples = append(samples, time.Since(start))
			}
			reportPercentiles(b, samples)
		})
	}
}

func BenchmarkSDK(b *testing.B) {
	url := startServer(b, 100)
	client, err := secretkit.New(url, secretkit.WithToken(benchToken))
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	// Warm the connection pool so the numbers measure steady-state requests.
	if _, err := client.GetSecret(ctx, "SECRET_000"); err != nil {
		b.Fatal(err)
	}

	b.Run("GetSecret", func(b *testing.B) {
		samples := make([]time.Duration, 0, b.N)
		for b.Loop() {
			start := time.Now()
			if _, err := client.GetSecret(ctx, "SECRET_042"); err != nil {
				b.Fatal(err)
			}
			samples = append(samples, time.Since(start))
		}
		reportPercentiles(b, samples)
	})
	b.Run("PutSecret", func(b *testing.B) {
		samples := make([]time.Duration, 0, b.N)
		for b.Loop() {
			start := time.Now()
			if _, err := client.PutSecret(ctx, "BENCH_PUT", "fake-value-for-benchmarks"); err != nil {
				b.Fatal(err)
			}
			samples = append(samples, time.Since(start))
		}
		reportPercentiles(b, samples)
	})
	b.Run("ListSecrets-100", func(b *testing.B) {
		samples := make([]time.Duration, 0, b.N)
		for b.Loop() {
			start := time.Now()
			if _, err := client.ListSecrets(ctx); err != nil {
				b.Fatal(err)
			}
			samples = append(samples, time.Since(start))
		}
		reportPercentiles(b, samples)
	})
	b.Run("GetSecret-parallel", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if _, err := client.GetSecret(ctx, "SECRET_042"); err != nil {
					b.Error(err)
					return
				}
			}
		})
	})
}

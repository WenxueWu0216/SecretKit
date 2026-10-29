# Benchmarks

All numbers on this page were measured once, on the machine below, with the
command below. They are not estimates. Expect different absolute numbers on
other hardware; re-run the command to get your own.

## How to run

```bash
go test -run '^$' -bench . -benchmem -count 5 ./bench/ ./internal/redact/
```

`bench/bench_test.go` builds a stripped CLI binary (`-trimpath -ldflags "-s -w"`)
in `TestMain` and starts the in-memory mock server in-process on a loopback
TCP port (`httptest.NewServer`). Each benchmark ran 5 times (`-count 5`) for
the default 1s benchtime.

## Machine

| | |
|---|---|
| CPU | Intel(R) Xeon(R) Processor @ 2.10GHz, 4 vCPUs (`GOMAXPROCS=4`) |
| Memory | 15 GiB |
| OS | Ubuntu 24.04.5 LTS, Linux 6.18.44 (cloud container, shared host) |
| Go | go1.25.3 linux/amd64 |
| Date | 2026-10-29 |

## Results

Median of 5 runs, with the min–max range across runs in parentheses.
`p50`/`p99` are per-request latency percentiles within each run, reported as
custom benchmark metrics.

### CLI cold start

Each iteration starts a new `secretkit` process and waits for it to exit,
so this includes process creation, Go runtime start-up and, for `get` and
`run`, real HTTP requests to the local server. Auth uses `SECRETKIT_TOKEN`
(no keychain access).

| Command | Mean | p50 | p99 |
|---|---|---|---|
| `secretkit --version` | 3.86 ms (3.79–4.15) | 3.72 ms (3.64–3.92) | 5.67 ms (4.75–6.37) |
| `secretkit get SECRET_001` | 4.94 ms (4.60–5.04) | 4.69 ms (4.45–4.83) | 7.86 ms (6.40–8.32) |
| `secretkit run -- true` (10 secrets: 1 list + 10 gets + child process) | 9.23 ms (8.73–9.63) | 9.09 ms (8.55–9.31) | 12.48 ms (11.50–13.82) |

The `B/op` and `allocs/op` columns in the raw output for these benchmarks
measure the benchmark harness (spawning the process), not the CLI itself.

### SDK request latency

One `secretkit.Client` with a warm keep-alive connection, against the mock
server over loopback.

| Operation | Mean | p50 | p99 |
|---|---|---|---|
| `GetSecret` | 101 µs (93–114) | 88 µs (83–98) | 324 µs (281–340) |
| `PutSecret` | 124 µs (120–131) | 107 µs (104–113) | 375 µs (353–410) |
| `ListSecrets` (100 secrets) | 451 µs (418–453) | 410 µs (380–419) | 1116 µs (1036–1273) |
| `GetSecret`, 4 goroutines (`b.RunParallel`) | 33 µs per op (29–34) | – | – |

The parallel number is wall time divided by total operations, i.e. about
30,000 requests per second across 4 goroutines.

### Redaction throughput

`internal/redact` `BenchmarkWriter`: a 744-byte line containing one secret,
two secrets registered.

| Mean | Throughput | Allocations |
|---|---|---|
| 709 ns/op (706–796) | 1050 MB/s (934–1055) | 0 B/op |

## Raw output

```text
goos: linux
goarch: amd64
pkg: github.com/WenxueWu0216/SecretKit/bench
cpu: Intel(R) Xeon(R) Processor @ 2.10GHz
BenchmarkCLIColdStart/version-4         	     279	   4154555 ns/op	      3915 p50-µs	      6255 p99-µs	   33472 B/op	      51 allocs/op
BenchmarkCLIColdStart/version-4         	     289	   4080662 ns/op	      3877 p50-µs	      6370 p99-µs	   33397 B/op	      51 allocs/op
BenchmarkCLIColdStart/version-4         	     301	   3863257 ns/op	      3715 p50-µs	      5331 p99-µs	   33407 B/op	      51 allocs/op
BenchmarkCLIColdStart/version-4         	     330	   3792495 ns/op	      3661 p50-µs	      4752 p99-µs	   33349 B/op	      51 allocs/op
BenchmarkCLIColdStart/version-4         	     326	   3839641 ns/op	      3642 p50-µs	      5668 p99-µs	   33362 B/op	      51 allocs/op
BenchmarkCLIColdStart/get-4             	     246	   4935636 ns/op	      4691 p50-µs	      8204 p99-µs	   37672 B/op	     104 allocs/op
BenchmarkCLIColdStart/get-4             	     240	   4974213 ns/op	      4744 p50-µs	      7861 p99-µs	   37349 B/op	     103 allocs/op
BenchmarkCLIColdStart/get-4             	     241	   4778508 ns/op	      4642 p50-µs	      6395 p99-µs	   37612 B/op	     103 allocs/op
BenchmarkCLIColdStart/get-4             	     268	   4600498 ns/op	      4448 p50-µs	      6883 p99-µs	   37449 B/op	     103 allocs/op
BenchmarkCLIColdStart/get-4             	     235	   5044828 ns/op	      4828 p50-µs	      8318 p99-µs	   37501 B/op	     103 allocs/op
BenchmarkCLIColdStart/run-true-4        	     130	   9058652 ns/op	      8870 p50-µs	     11648 p99-µs	   65326 B/op	     450 allocs/op
BenchmarkCLIColdStart/run-true-4        	     135	   8728467 ns/op	      8554 p50-µs	     12516 p99-µs	   65190 B/op	     449 allocs/op
BenchmarkCLIColdStart/run-true-4        	     123	   9631660 ns/op	      9305 p50-µs	     13819 p99-µs	   65079 B/op	     449 allocs/op
BenchmarkCLIColdStart/run-true-4        	     130	   9320140 ns/op	      9194 p50-µs	     12482 p99-µs	   64874 B/op	     449 allocs/op
BenchmarkCLIColdStart/run-true-4        	     130	   9230068 ns/op	      9089 p50-µs	     11499 p99-µs	   64916 B/op	     449 allocs/op
BenchmarkSDK/GetSecret-4                	   10411	    114053 ns/op	        98.00 p50-µs	       324.0 p99-µs	    9953 B/op	     119 allocs/op
BenchmarkSDK/GetSecret-4                	   10000	    100951 ns/op	        88.00 p50-µs	       324.0 p99-µs	    9949 B/op	     119 allocs/op
BenchmarkSDK/GetSecret-4                	   12766	     92947 ns/op	        83.00 p50-µs	       281.0 p99-µs	    9953 B/op	     119 allocs/op
BenchmarkSDK/GetSecret-4                	   12145	    100241 ns/op	        86.00 p50-µs	       339.0 p99-µs	    9944 B/op	     119 allocs/op
BenchmarkSDK/GetSecret-4                	   11372	    107144 ns/op	        91.00 p50-µs	       340.0 p99-µs	    9948 B/op	     119 allocs/op
BenchmarkSDK/PutSecret-4                	    8236	    124375 ns/op	       107.0 p50-µs	       370.0 p99-µs	   11631 B/op	     142 allocs/op
BenchmarkSDK/PutSecret-4                	    9903	    120117 ns/op	       104.0 p50-µs	       353.0 p99-µs	   11617 B/op	     142 allocs/op
BenchmarkSDK/PutSecret-4                	   10000	    124363 ns/op	       106.0 p50-µs	       375.0 p99-µs	   11615 B/op	     142 allocs/op
BenchmarkSDK/PutSecret-4                	    8318	    128226 ns/op	       110.0 p50-µs	       410.0 p99-µs	   11638 B/op	     142 allocs/op
BenchmarkSDK/PutSecret-4                	   10000	    130517 ns/op	       113.0 p50-µs	       383.0 p99-µs	   11615 B/op	     142 allocs/op
BenchmarkSDK/ListSecrets-100-4          	    2647	    418394 ns/op	       380.0 p50-µs	      1036 p99-µs	   70966 B/op	     343 allocs/op
BenchmarkSDK/ListSecrets-100-4          	    3198	    451238 ns/op	       419.0 p50-µs	      1116 p99-µs	   70890 B/op	     343 allocs/op
BenchmarkSDK/ListSecrets-100-4          	    2700	    446080 ns/op	       410.0 p50-µs	      1052 p99-µs	   70887 B/op	     343 allocs/op
BenchmarkSDK/ListSecrets-100-4          	    3312	    451403 ns/op	       410.0 p50-µs	      1123 p99-µs	   70844 B/op	     343 allocs/op
BenchmarkSDK/ListSecrets-100-4          	    2718	    452615 ns/op	       400.0 p50-µs	      1273 p99-µs	   70856 B/op	     343 allocs/op
BenchmarkSDK/GetSecret-parallel-4       	   35778	     33496 ns/op	   11458 B/op	     126 allocs/op
BenchmarkSDK/GetSecret-parallel-4       	   33828	     34175 ns/op	   11448 B/op	     126 allocs/op
BenchmarkSDK/GetSecret-parallel-4       	   37393	     33067 ns/op	   11483 B/op	     126 allocs/op
BenchmarkSDK/GetSecret-parallel-4       	   39854	     29296 ns/op	   11471 B/op	     126 allocs/op
BenchmarkSDK/GetSecret-parallel-4       	   38866	     32874 ns/op	   11556 B/op	     126 allocs/op
goos: linux
goarch: amd64
pkg: github.com/WenxueWu0216/SecretKit/internal/redact
cpu: Intel(R) Xeon(R) Processor @ 2.10GHz
BenchmarkWriter-4   	 1680213	       706.1 ns/op	1053.61 MB/s	       0 B/op	       0 allocs/op
BenchmarkWriter-4   	 1570474	       796.3 ns/op	 934.35 MB/s	       0 B/op	       0 allocs/op
BenchmarkWriter-4   	 1840716	       708.9 ns/op	1049.57 MB/s	       0 B/op	       0 allocs/op
BenchmarkWriter-4   	 1747606	       705.5 ns/op	1054.58 MB/s	       0 B/op	       0 allocs/op
BenchmarkWriter-4   	 1649164	       757.7 ns/op	 981.90 MB/s	       0 B/op	       0 allocs/op
```

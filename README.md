# Build an OPA Bundle with WASM Policy

```bash
git clone https://github.com/nikpivkin/trivy-checks
cd trivy-checks
git checkout opa-bundle
make build-opa-bundle
```

# Benchmarks
```bash
❯ make benchmark
go test -bench=. -benchmem
goos: darwin
goarch: arm64
pkg: test
cpu: Apple M1
BenchmarkRegoChecksWithLoad-8                  5         214656717 ns/op        120855673 B/op   2271817 allocs/op
BenchmarkWasmChecksWithLoad-8                  1        3144039042 ns/op        1612962680 B/op  3533409 allocs/op
BenchmarkRegoChecks-8                         18          64635005 ns/op        24844341 B/op     390555 allocs/op
BenchmarkWasmChecks-8                          1        3148738791 ns/op        1612381384 B/op  3531795 allocs/op
BenchmarkRegoChecksOneQuery-8                 56          18768454 ns/op        11789150 B/op     162972 allocs/op
BenchmarkWasmChecksOneQuery-8                  1        2885350833 ns/op        1385517664 B/op  1197948 allocs/op
PASS
ok      test    18.292s
```

# Performance Comparison: Rego vs WASM

## Large input (527K)

### Rego

```bash
❯ time go run . -rego-checks=./trivy-checks/checks,./trivy-checks/lib -input=large-input.yaml
go run . -rego-checks=./trivy-checks/checks,./trivy-checks/lib   2.07s user 1.12s system 123% cpu 2.586 total
```

### WASM

```bash
❯ time go run . -bundles=./trivy-checks/bundle.tar.gz -input=large-input.yaml
go run . -bundles=./trivy-checks/bundle.tar.gz -input=large-input.yaml  6.10s user 1.23s system 141% cpu 5.166 total
```

## Small input (5.2K)

### Rego

```bash
❯ time go run . -rego-checks=./trivy-checks/checks,./trivy-checks/lib -input=small-input.yaml
go run . -rego-checks=./trivy-checks/checks,./trivy-checks/lib   1.96s user 0.93s system 66% cpu 4.325 total
```

### WASM

```bash
❯ time go run . -bundles=./trivy-checks/bundle.tar.gz -input=small-input.yaml
go run . -bundles=./trivy-checks/bundle.tar.gz -input=small-input.yaml  3.06s user 0.88s system 96% cpu 4.087 total
```
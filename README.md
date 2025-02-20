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
pkg: github.com/nikpivkin/wasm-checks
cpu: Apple M1
BenchmarkRegoChecksWithLoad-8                  5         241544900 ns/op        113586585 B/op   1973174 allocs/op
BenchmarkWasmChecksWithLoad-8                  1        3190281041 ns/op        1604378952 B/op  3461353 allocs/op
BenchmarkRegoChecks-8                         18          59726509 ns/op        22724456 B/op     343297 allocs/op
BenchmarkWasmChecks-8                          1        3174330541 ns/op        1603826616 B/op  3459758 allocs/op
BenchmarkRegoChecksOneQuery-8                 60          17161990 ns/op        11157759 B/op     138003 allocs/op
BenchmarkWasmChecksOneQuery-8                  1        2862104750 ns/op        1384479280 B/op  1139169 allocs/op
BenchmarkUseWasmDirectly-8                    37          27840310 ns/op        11470507 B/op     127631 allocs/op
PASS
ok      github.com/nikpivkin/wasm-checks        20.245s
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
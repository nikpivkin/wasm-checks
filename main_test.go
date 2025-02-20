package main

import (
	"os"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"
)

func init() {
	// log.SetOutput(io.Discard)
}

func BenchmarkRegoChecksWithLoad(b *testing.B) {
	input := must(os.ReadFile("input.yaml"))
	for i := 0; i < b.N; i++ {
		run([]string{"./trivy-checks/checks", "./trivy-checks/lib"}, nil, input)
	}
}

func BenchmarkWasmChecksWithLoad(b *testing.B) {
	input := must(os.ReadFile("input.yaml"))
	for i := 0; i < b.N; i++ {
		run(nil, []string{"./trivy-checks/bundle.tar.gz"}, input)
	}
}

func BenchmarkRegoChecks(b *testing.B) {
	opts, queries := initOptions([]string{"./trivy-checks/checks", "./trivy-checks/lib"}, nil)
	input := must(os.ReadFile("input.yaml"))
	astVal := must(parseRawInput(input))
	opts = append(opts, rego.ParsedInput(astVal))
	for i := 0; i < b.N; i++ {
		runQuerirs(queries, opts)
	}
}

func BenchmarkWasmChecks(b *testing.B) {
	opts, queries := initOptions(nil, []string{"./trivy-checks/bundle.tar.gz"})
	input := must(os.ReadFile("input.yaml"))
	astVal := must(parseRawInput(input))
	opts = append(opts, rego.ParsedInput(astVal))
	for i := 0; i < b.N; i++ {
		runQuerirs(queries, opts)
	}
}

func BenchmarkRegoChecksOneQuery(b *testing.B) {
	input := must(os.ReadFile("input.yaml"))
	opts, _ := initOptions([]string{"./trivy-checks/checks", "./trivy-checks/lib"}, nil)
	for i := 0; i < b.N; i++ {
		runBuiltinQuery(input, opts)
	}
}

func BenchmarkWasmChecksOneQuery(b *testing.B) {
	input := must(os.ReadFile("input.yaml"))
	opts, _ := initOptions(nil, []string{"./trivy-checks/bundle.tar.gz"})
	for i := 0; i < b.N; i++ {
		runBuiltinQuery(input, opts)
	}
}

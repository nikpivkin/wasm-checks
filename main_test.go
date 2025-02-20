package main

import (
	"context"
	"log"
	"os"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/resolver"
	"github.com/open-policy-agent/opa/v1/resolver/wasm"
)

func init() {
	// log.SetOutput(io.Discard)
}

func BenchmarkRegoChecksWithLoad(b *testing.B) {
	input := must(os.ReadFile("large-input.yaml"))
	for i := 0; i < b.N; i++ {
		run([]string{"./trivy-checks/checks", "./trivy-checks/lib"}, nil, input)
	}
}

func BenchmarkWasmChecksWithLoad(b *testing.B) {
	input := must(os.ReadFile("large-input.yaml"))
	for i := 0; i < b.N; i++ {
		run(nil, []string{"./trivy-checks/bundle.tar.gz"}, input)
	}
}

func BenchmarkRegoChecks(b *testing.B) {
	opts, queries := initOptions([]string{"./trivy-checks/checks", "./trivy-checks/lib"}, nil)
	input := must(os.ReadFile("large-input.yaml"))
	astVal := must(parseRawInput(input))
	opts = append(opts, rego.ParsedInput(astVal))
	for i := 0; i < b.N; i++ {
		runQuerirs(queries, opts)
	}
}

func BenchmarkWasmChecks(b *testing.B) {
	opts, queries := initOptions(nil, []string{"./trivy-checks/bundle.tar.gz"})
	input := must(os.ReadFile("large-input.yaml"))
	astVal := must(parseRawInput(input))
	opts = append(opts, rego.ParsedInput(astVal))
	for i := 0; i < b.N; i++ {
		runQuerirs(queries, opts)
	}
}

func BenchmarkRegoChecksOneQuery(b *testing.B) {
	input := must(os.ReadFile("large-input.yaml"))
	opts, _ := initOptions([]string{"./trivy-checks/checks", "./trivy-checks/lib"}, nil)
	for i := 0; i < b.N; i++ {
		runBuiltinQuery(input, opts)
	}
}

func BenchmarkWasmChecksOneQuery(b *testing.B) {
	input := must(os.ReadFile("large-input.yaml"))
	opts, _ := initOptions(nil, []string{"./trivy-checks/bundle.tar.gz"})
	for i := 0; i < b.N; i++ {
		runBuiltinQuery(input, opts)
	}
}

func BenchmarkUseWasmDirectly(b *testing.B) {
	bundles := loadBundles("./trivy-checks/bundle.tar.gz")
	bndl := bundles[0]
	wasmModule := bndl.WasmModules[0]

	r := must(wasm.New(wasmModule.Entrypoints, wasmModule.Raw, nil))

	input := must(os.ReadFile("large-input.yaml"))
	var raw any = input

	for i := 0; i < b.N; i++ {
		for _, entrypoint := range wasmModule.Entrypoints {
			log.Println(entrypoint.String())
			result := must(r.Eval(context.TODO(), resolver.Input{
				Ref:      entrypoint,
				RawInput: &raw,
			}))
			_ = result

		}
	}
}

package main

import (
	"context"
	"flag"
	"io/fs"
	"log"
	"os"
	"runtime/pprof"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/loader"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/resolver/wasm"
	"github.com/open-policy-agent/opa/v1/util"

	r "github.com/aquasecurity/trivy-checks/pkg/rego"
	_ "github.com/aquasecurity/trivy/pkg/iac/rego"        // register Built-in Functions from Trivy
	_ "github.com/open-policy-agent/opa/v1/features/wasm" // enable WASM feature
)

func main() {
	r.RegisterBuiltins()
	regoChecks := flag.String("rego-checks", "", "comma-separated paths to directories with Rego checks")
	bundles := flag.String("bundles", "", "comma-separated paths to bundles with WASM checks")
	input := flag.String("input", "", "path to input file")
	flag.Parse()

	cpuProfile, _ := os.Create("cpu.prof")
	defer cpuProfile.Close()
	pprof.StartCPUProfile(cpuProfile)
	defer pprof.StopCPUProfile()

	b := must(os.ReadFile(*input))
	// run(
	// 	skipEmptyEl(strings.Split(*regoChecks, ",")),
	// 	skipEmptyEl(strings.Split(*bundles, ",")),
	// 	input)

	opts, _ := initOptions(
		skipEmptyEl(strings.Split(*regoChecks, ",")),
		skipEmptyEl(strings.Split(*bundles, ",")))
	runBuiltinQuery(b, opts)
}

func skipEmptyEl(s []string) []string {
	var res []string
	for _, el := range s {
		if el != "" {
			res = append(res, el)
		}
	}
	return res
}

func run(regoChecks, bundles []string, input any) {
	opts, queries := initOptions(regoChecks, bundles)
	astVal := must(parseRawInput(input))
	opts = append(opts, rego.ParsedInput(astVal))
	runQuerirs(queries, opts)
}

func runQuerirs(queries []string, opts []func(*rego.Rego)) {
	for _, query := range queries {
		runQuery(query, opts)
	}
}

func runQuery(query string, opts []func(*rego.Rego)) {
	log.Println("Query:", query)
	regoOpts := []func(*rego.Rego){
		rego.Query(query),
	}

	regoOpts = append(regoOpts, opts...)
	r := rego.New(regoOpts...)
	resultSet := must(r.Eval(context.TODO()))

	for _, res := range resultSet {
		for _, expr := range res.Expressions {
			log.Println("Result:", expr.String())
		}
	}
}

func runBuiltinQuery(input any, opts []func(*rego.Rego)) {
	const query = "data.builtin"
	log.Println("Query:", query)
	regoOpts := []func(*rego.Rego){
		rego.Query(query),
		rego.Input(input),
	}

	regoOpts = append(regoOpts, opts...)
	r := rego.New(regoOpts...)
	resultSet := must(r.Eval(context.TODO()))

	// TODO: filter after eval
	for _, res := range resultSet {
		for _, expr := range res.Expressions {
			log.Println("Result:", expr.String())
		}
	}
}

func initOptions(regoChecks, bundles []string) ([]func(*rego.Rego), []string) {
	var opts []func(*rego.Rego)
	var queries []string

	if len(regoChecks) > 0 {
		c := buildCompiler(regoChecks...)
		opts = append(opts, rego.Compiler(c))
		for _, m := range c.Modules {
			queries = append(queries, queryFromRef(m.Package.Path))
		}

	}

	if len(bundles) > 0 {
		for _, b := range loadBundles(bundles...) {
			for _, wasmModule := range b.WasmModules {
				r := must(wasm.New(wasmModule.Entrypoints, wasmModule.Raw, nil))
				for _, entrypoint := range r.Entrypoints() {
					opts = append(opts, rego.Resolver(entrypoint, r))
					queries = append(queries, queryFromRef(entrypoint))
				}
			}
		}
	}
	return opts, queries
}

func queryFromRef(ref ast.Ref) string {
	return ref.String() + ".deny"
}

func loadBundles(paths ...string) []*bundle.Bundle {
	var bundles []*bundle.Bundle
	for _, p := range paths {
		fl := loader.NewFileLoader().WithFilter(onlyRegoFilter)
		bundles = append(bundles, must(fl.AsBundle(p)))
	}
	return bundles
}

func buildCompiler(paths ...string) *ast.Compiler {
	loaded := must(loader.NewFileLoader().Filtered(paths, onlyRegoFilter))
	c := ast.NewCompiler()
	c.Compile(loaded.ParsedModules())
	if c.Failed() {
		panic(c.Errors)
	}
	return c
}

func onlyRegoFilter(abspath string, info fs.FileInfo, depth int) bool {
	return strings.HasSuffix(info.Name(), "_test"+bundle.RegoExt) || strings.HasSuffix(info.Name(), ".yaml")
}

func parseRawInput(input any) (ast.Value, error) {
	if err := util.RoundTrip(&input); err != nil {
		return nil, err
	}

	return ast.InterfaceToValue(input)
}

func must[T any](val T, err error) T {
	if err != nil {
		panic(err)
	}
	return val
}

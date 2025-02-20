extract-wasm:
	tar -zxf trivy-checks/bundle.tar.gz /policy.wasm

wasm2wat: extract-wasm
	wasm2wat policy.wasm > policy.wat

optimize-wasm: extract-wasm
	wasm-opt -O2 policy.wasm -o policy-opt.wasm 
	
run-bundle:
	go run . -bundles=./trivy-checks/bundle.tar.gz -input=large-input.yaml

run-rego:
	go run . -rego-checks=./trivy-checks/checks,./trivy-checks/lib -input=large-input.yaml

benchmark:
	go test -bench=. -benchmem

generate-yaml:
	echo "---" > input.yaml && \
	echo "apiVersion: v1" >> input.yaml && \
	echo "kind: List" >> input.yaml && \
	echo "items:" >> input.yaml && \
	seq 10 | awk '{printf "- apiVersion: v1\n  kind: ConfigMap\n  metadata:\n    name: configmap-%s\n    namespace: default\n  data:\n    key%s: value%s\n", $$1, $$1, $$1}' >> input.yaml

clean:
	rm *.wasm *.wat



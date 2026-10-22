# Образ оператора.
IMG ?= prorobotech/kaname-iam-operator:dev

ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

CONTAINER_TOOL ?= docker

SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

CHART_DIR := charts/kaname-iam-operator

.PHONY: all
all: build

##@ General

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate CRDs and RBAC; mirror CRDs into the chart.
	"$(CONTROLLER_GEN)" crd paths="./api/..." output:crd:artifacts:config=config/crd/bases
	"$(CONTROLLER_GEN)" rbac:roleName=manager-role paths="./internal/controller/..." output:rbac:artifacts:config=config/rbac
	@grep -q apiGroups config/rbac/role.yaml || { echo "manifests: config/rbac/role.yaml has no rules"; exit 1; }
	mkdir -p $(CHART_DIR)/crds
	cp config/crd/bases/*.yaml $(CHART_DIR)/crds/

.PHONY: generate
generate: controller-gen ## Generate DeepCopy methods.
	"$(CONTROLLER_GEN)" object:headerFile="hack/boilerplate.go.txt" paths="./api/..."

.PHONY: fmt
fmt: ## Run go fmt.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet.
	go vet ./...
	go vet -tags=integration ./test/integration/...
	go vet -tags=e2e ./test/e2e/...

.PHONY: verify-generated
verify-generated: manifests generate ## Fail when generated files differ from the tree.
	@git diff --exit-code -- api config $(CHART_DIR)/crds || { echo "generated files are stale: run make manifests generate"; exit 1; }

.PHONY: test
test: manifests generate fmt vet setup-envtest ## Run unit and envtest suites.
	KUBEBUILDER_ASSETS="$(shell "$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path)" \
		go test ./... -count=1 -coverprofile cover.out -json > test-report.json || { $(MAKE) --no-print-directory test-summary; exit 1; }
	@$(MAKE) --no-print-directory test-summary

.PHONY: test-summary
test-summary: ## Print counts of executed tests from test-report.json.
	@go run ./hack/testsummary test-report.json

.PHONY: test-integration
test-integration: manifests generate setup-envtest ## Run integration suites (testcontainers Vault, kaname stand).
	KUBEBUILDER_ASSETS="$(shell "$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path)" \
		go test -tags=integration ./test/integration/... -count=1 -v -timeout 30m

KIND_CLUSTER ?= kaname-iam-operator-test-e2e

.PHONY: setup-test-e2e
setup-test-e2e: ## Create the kind cluster for e2e if absent.
	@command -v $(KIND) >/dev/null 2>&1 || { echo "kind is not installed"; exit 1; }
	@case "$$($(KIND) get clusters)" in \
		*"$(KIND_CLUSTER)"*) echo "kind cluster $(KIND_CLUSTER) exists" ;; \
		*) $(KIND) create cluster --name $(KIND_CLUSTER) ;; \
	esac

.PHONY: test-e2e
test-e2e: setup-test-e2e manifests generate ## Run e2e on kind (chart install, admission policies, CRD validation); tears the cluster down.
	trap '$(KIND) delete cluster --name $(KIND_CLUSTER)' EXIT; \
		KIND=$(KIND) KIND_CLUSTER=$(KIND_CLUSTER) IMG=$(IMG) go test -tags=e2e ./test/e2e/ -count=1 -v -timeout 30m

.PHONY: lint
lint: golangci-lint ## Run golangci-lint.
	"$(GOLANGCI_LINT)" run ./...
	"$(GOLANGCI_LINT)" run --build-tags=integration ./test/integration/...
	"$(GOLANGCI_LINT)" run --build-tags=e2e ./test/e2e/...

.PHONY: lint-config
lint-config: golangci-lint ## Verify golangci-lint configuration.
	"$(GOLANGCI_LINT)" config verify

.PHONY: helm-lint
helm-lint: ## Lint and render the chart.
	helm lint $(CHART_DIR)
	helm template t $(CHART_DIR) --namespace kaname-iam-system >/dev/null

##@ Build

.PHONY: build
build: manifests generate fmt vet ## Build the manager binary.
	go build -o bin/manager ./cmd

.PHONY: run
run: manifests generate fmt vet ## Run the manager from the host.
	go run ./cmd

.PHONY: docker-build
docker-build: ## Build the manager image.
	$(CONTAINER_TOOL) build -t ${IMG} .

.PHONY: docker-push
docker-push: ## Push the manager image.
	$(CONTAINER_TOOL) push ${IMG}

##@ Dependencies

LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p "$(LOCALBIN)"

KUBECTL ?= kubectl
KIND ?= kind
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint

CONTROLLER_TOOLS_VERSION ?= v0.23.0
GOLANGCI_LINT_VERSION ?= v2.12.2

ENVTEST_VERSION ?= $(shell v='$(call gomodver,sigs.k8s.io/controller-runtime)'; \
  [ -n "$$v" ] || { echo "Set ENVTEST_VERSION manually" >&2; exit 1; }; \
  printf '%s\n' "$$v" | sed -E 's/^v?([0-9]+)\.([0-9]+).*/release-\1.\2/')

ENVTEST_K8S_VERSION ?= $(shell v='$(call gomodver,k8s.io/api)'; \
  [ -n "$$v" ] || { echo "Set ENVTEST_K8S_VERSION manually" >&2; exit 1; }; \
  printf '%s\n' "$$v" | sed -E 's/^v?[0-9]+\.([0-9]+).*/1.\1/')

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

.PHONY: setup-envtest
setup-envtest: envtest ## Download envtest binaries.
	@"$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path >/dev/null || { \
		echo "Error: failed to set up envtest binaries for $(ENVTEST_K8S_VERSION)"; exit 1; }

.PHONY: envtest
envtest: $(ENVTEST) ## Download setup-envtest locally if necessary.
$(ENVTEST): $(LOCALBIN)
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(ENVTEST_VERSION))

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))

define go-install-tool
@[ -f "$(1)-$(3)" ] && [ "$$(readlink -- "$(1)" 2>/dev/null)" = "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f "$(1)" ;\
GOBIN="$(LOCALBIN)" go install $${package} ;\
mv "$(LOCALBIN)/$$(basename "$(1)")" "$(1)-$(3)" ;\
} ;\
ln -sf "$$(realpath "$(1)-$(3)")" "$(1)"
endef

define gomodver
$(shell go list -m -f '{{if .Replace}}{{.Replace.Version}}{{else}}{{.Version}}{{end}}' $(1) 2>/dev/null)
endef

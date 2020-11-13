.DEFAULT_GOAL:=help

TOOLS_DIR     := hack/tools
TOOLS_BIN_DIR := $(TOOLS_DIR)/bin
GOLANGCI_LINT := $(TOOLS_BIN_DIR)/golangci-lint
GOBINDATA     := $(TOOLS_BIN_DIR)/go-bindata
REPO_ROOT     := github.com/criticalstack/swoll

GIT_COMMIT := $(shell git log --pretty=format:%h -n 1)
BUILD_DATE := $(shell date +%Y.%m.%d.%H%M%S)

FLAGS   := -a -tags=netgo,osusergo
FLAGS   += -gcflags "all=-trimpath=$(PWD)"
FLAGS   += -asmflags "all=-trimpath=$(PWD)"
LDFLAGS ?= -s -w
LDFLAGS += -linkmode external -extldflags '-static'
LDFLAGS += -X "$(REPO_ROOT)/cmd.buildTime=$(BUILD_DATE)"
LDFLAGS += -X "$(REPO_ROOT)/cmd.gitCommit=$(GIT_COMMIT)"

ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

##@ Building

.PHONY: swoll

bpf: ## Build the BPF probe
	@echo "Building kernel probe..."
	$(MAKE) -s -C internal/bpf build

swoll: bindata ## Build the swoll binary
	@echo "Building Swoll..."
	@mkdir -p bin/
	go build $(FLAGS) -ldflags '$(LDFLAGS)' -o bin/swoll main.go

## Build the BPF probe and generate embedded asset file
bindata: $(GOBINDATA) bpf
	$(GOBINDATA) -nometadata -nocompress -pkg assets -tags !nobindata -o internal/pkg/assets/bindata.go ./internal/bpf/probe*.o

all: bpf bindata generate cmd/ internal/bpf swoll ## Build the BPF probe and swoll binary

CRD_OPTIONS ?= "crd:crdVersions=v1"
IMG ?= controller:latest

# Generate code
generate: controller-gen
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

# Generate manifests e.g. CRD, RBAC etc.
manifests: controller-gen
	$(CONTROLLER_GEN) $(CRD_OPTIONS) rbac:roleName=manager-role webhook paths="./..." output:crd:artifacts:config=config/crd/bases

deploy: manifests
	cd config/manager && kustomize edit set image controller=${IMG}
	kustomize build config/default | kubectl apply -f -

install: manifests
	kustomize build config/crd | kubectl apply -f -

# find or download controller-gen 
controller-gen:
ifeq (, $(shell which controller-gen))
	@{ \
    set -e ;\
    CONTROLLER_GEN_TMP_DIR=$$(mktemp -d) ;\
    cd $$CONTROLLER_GEN_TMP_DIR ;\
    go mod init tmp ;\
    go get sigs.k8s.io/controller-tools/cmd/controller-gen@v0.3.0 ;\
    rm -rf $$CONTROLLER_GEN_TMP_DIR ;\
    }
CONTROLLER_GEN=$(GOBIN)/controller-gen
else
CONTROLLER_GEN=$(shell which controller-gen)
endif

build-chart:
	kustomize build config/crd > helm/templates/crds/crds.yaml 

##@ Testing

.PHONY: lint

test: ## Run all tests
	@go test -tags nobindata -v ./pkg/...
	@go test -tags nobindata -v ./internal/pkg/...

lint: $(GOLANGCI_LINT) ## Lint codebase
	$(GOLANGCI_LINT) run -v

lint-full: $(GOLANGCI_LINT) ## Run slower linters to detect possible issues
	$(GOLANGCI_LINT) run -v --build-tags nobindata --fast=false

##@ Helpers

.PHONY: help

clean:
	@echo "Cleaning up..."
	@rm -rf bin/swoll
	@$(MAKE) -C internal/bpf clean

$(GOLANGCI_LINT): $(TOOLS_DIR) # Build golangci-lint from tools folder.
	cd $(TOOLS_DIR); go build -tags=tools -o bin/golangci-lint github.com/golangci/golangci-lint/cmd/golangci-lint

$(GOBINDATA): # Build go-bindata from tools folder.
	cd $(TOOLS_DIR); go build -tags=tools -o bin/go-bindata github.com/go-bindata/go-bindata/go-bindata

help:  ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

BINARY    := nomore403
MODULE    := github.com/mr-pmillz/nomore403
MAIN      := ./cmd/nomore403
BUILD_DIR := bin
COVER_DIR := coverage
IMAGE     := ghcr.io/mr-pmillz/nomore403

VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT     := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(MODULE).version=$(VERSION) \
	-X $(MODULE).commit=$(COMMIT) \
	-X $(MODULE).date=$(BUILD_DATE)

.PHONY: all build test test-race test-coverage lint fmt vet install clean tidy docker docker-run snapshot help

all: lint test build

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

build: ## Build the binary into bin/
	@mkdir -p $(BUILD_DIR)
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) $(MAIN)

test: ## Run all tests
	@if ! command -v tparse >/dev/null 2>&1; then \
			echo "tparse not installed; installing..."; \
			go install github.com/mfridman/tparse@latest; \
	fi
	@echo "🧪 Running all tests..."
	@mkdir -p $(COVER_DIR)
	go test -json -covermode=atomic -coverprofile=$(COVER_DIR)/coverage.out ./... | tparse -all

test-race: ## Run all tests with the race detector
	go test ./... -count=1 -race

test-coverage: ## Run tests and write an HTML coverage report
	@mkdir -p $(COVER_DIR)
	go test ./... -count=1 -race -coverprofile=$(COVER_DIR)/coverage.out -covermode=atomic
	go tool cover -func=$(COVER_DIR)/coverage.out
	go tool cover -html=$(COVER_DIR)/coverage.out -o $(COVER_DIR)/coverage.html
	@echo "Coverage report: $(COVER_DIR)/coverage.html"

lint: ## Run golangci-lint
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not installed"; exit 1; }
	golangci-lint run --config .golangci-lint.yml -v --timeout 10m

fmt: ## Format the code
	go fmt ./...
	goimports -w .

vet: ## Run go vet
	go vet ./...

install: ## Install the binary into GOBIN
	go install -trimpath -ldflags "$(LDFLAGS)" $(MAIN)

docker: ## Build the container image locally (payloads are embedded in the binary)
	@mkdir -p dist/docker/linux/amd64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/docker/linux/amd64/$(BINARY) $(MAIN)
	cp Dockerfile dist/docker/Dockerfile
	docker build --build-arg TARGETPLATFORM=linux/amd64 -t $(IMAGE):$(VERSION) -t $(IMAGE):latest dist/docker

docker-run: docker ## Build and run the container image
	docker run --rm $(IMAGE):latest --help

snapshot: ## Build a local goreleaser snapshot (no publish)
	@command -v goreleaser >/dev/null 2>&1 || { echo "goreleaser not installed"; exit 1; }
	goreleaser release --snapshot --clean --skip=publish

clean: ## Remove build and coverage artifacts
	rm -rf $(BUILD_DIR) $(COVER_DIR) dist
	go clean

tidy: ## Tidy go.mod / go.sum
	go mod tidy

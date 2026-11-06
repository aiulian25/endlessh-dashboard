BINARY          := endlessh-dashboard
CMD_PACKAGE     := ./cmd/endlessh-dashboard
BIN_DIR         := bin
LOCAL_DATA_DIR  := ./data

VERSION         ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE           ?= $(BINARY):$(VERSION)
DATA_VOLUME     ?= endlessh-data

GO_LDFLAGS      := -s -w -X main.version=$(VERSION)

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@echo "endlessh-dashboard - make targets (VERSION=$(VERSION))"
	@echo
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the static binary into ./bin
	CGO_ENABLED=0 GOOS=linux go build \
		-trimpath \
		-ldflags="$(GO_LDFLAGS)" \
		-o $(BIN_DIR)/$(BINARY) \
		$(CMD_PACKAGE)

.PHONY: run
run: ## Run locally against ./data using the process environment
	@mkdir -p $(LOCAL_DATA_DIR)
	DATA_DIR=$(LOCAL_DATA_DIR) go run $(CMD_PACKAGE)

.PHONY: test
test: ## Run the unit tests
	go test ./...

.PHONY: test-race
test-race: ## Run the unit tests under the race detector
	go test -race -timeout=25m ./...

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: fmt
fmt: ## Format all Go source
	go fmt ./...

.PHONY: tidy
tidy: ## Tidy go.mod and go.sum
	go mod tidy

.PHONY: vuln
vuln: ## Scan dependencies for known vulnerabilities
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

.PHONY: docker-build
docker-build: ## Build the container image
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .

.PHONY: docker-run
docker-run: ## Run the image with the same hardening as docker-compose.yml
	docker run --rm --stop-timeout 20 \
		--name $(BINARY) \
		--env-file .env \
		-p 18222:18222 \
		-v $(DATA_VOLUME):/data \
		--tmpfs /tmp:rw,noexec,nosuid,size=32m \
		--read-only \
		--cap-drop ALL \
		--security-opt no-new-privileges:true \
		$(IMAGE)

.PHONY: e2e
e2e: ## Run the isolated real-exporter smoke test and verify cleanup
	@./e2e/run.sh

.PHONY: clean
clean: ## Remove build and test output
	rm -rf $(BIN_DIR) coverage.out coverage.html
	go clean -testcache

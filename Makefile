BINARY          := endlessh-dashboard
CMD_PACKAGE     := ./cmd/endlessh-dashboard
BIN_DIR         := bin
LOCAL_DATA_DIR  := ./data
E2E_COMPOSE     := e2e/docker-compose.e2e.yml

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
run: ## Run locally against ./data (reads .env if the app finds one)
	@mkdir -p $(LOCAL_DATA_DIR)
	DATA_DIR=$(LOCAL_DATA_DIR) go run $(CMD_PACKAGE)

.PHONY: test
test: ## Run the unit tests
	go test ./...

.PHONY: test-race
test-race: ## Run the unit tests under the race detector
	go test -race ./...

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
docker-run: ## Run the image with the same hardening as docker-compose.dev.yml
	docker run --rm \
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
e2e: docker-build ## Run the end-to-end smoke test against a real endlessh-go
	# The suite drives a live stack, so the target brings it up, runs the tests,
	# and tears it down again whatever the outcome. E2E=1 is what actually
	# enables the suite: without it every test skips and this target would
	# report success having asserted nothing.
	docker compose -f $(E2E_COMPOSE) up --build -d
	@E2E=1 IMAGE=$(IMAGE) E2E_COMPOSE=$(E2E_COMPOSE) \
		go test -count=1 -v -tags e2e -timeout 10m ./e2e/...; \
	status=$$?; \
	docker compose -f $(E2E_COMPOSE) down -v; \
	exit $$status

.PHONY: clean
clean: ## Remove build and test output
	rm -rf $(BIN_DIR) coverage.out coverage.html
	go clean -testcache

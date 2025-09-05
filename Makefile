# BrakeBear Makefile
# Docker container network bandwidth limiter

# Variables
BINARY_NAME=brakebear
BINARY_PATH=cmd/brakebear/main.go
BUILD_DIR=build
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME?=$(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

# Go build flags
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)"
GO_BUILD_FLAGS=-trimpath $(LDFLAGS)

# PHONY targets
.PHONY: all build clean test lint fmt vet check install uninstall
.PHONY: test-build-image test-up test-down test-up-all test-down-all test-cleanup test-script test-run-brakebear test-integration docker-test
.PHONY: orbstack-dev orbstack-dev-clean
.PHONY: help

# Default target
all: clean lint test build

# Build the application
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(BINARY_PATH)
	@echo "Built $(BUILD_DIR)/$(BINARY_NAME)"

# Build for development (faster, no optimizations)
build-dev:
	@echo "Building $(BINARY_NAME) for development..."
	go build -o $(BINARY_NAME) $(BINARY_PATH)
	@echo "Built $(BINARY_NAME)"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -f $(BINARY_NAME)
	go clean -cache -testcache -modcache

# Run tests
test:
	@echo "Running tests..."
	go test -race -v ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run benchmarks
bench:
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./...

# Lint the code
lint:
	@echo "Running linters..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run --new-from-rev="origin/master" || golangci-lint run; \
	else \
		echo "golangci-lint not found, install it with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
		exit 1; \
	fi

# Format the code
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Vet the code
vet:
	@echo "Running go vet..."
	go vet ./...

# Run all checks
check: fmt vet lint test

# Install the binary
install: build
	@echo "Installing $(BINARY_NAME)..."
	sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@echo "Installed to /usr/local/bin/$(BINARY_NAME)"

# Uninstall the binary
uninstall:
	@echo "Uninstalling $(BINARY_NAME)..."
	sudo rm -f /usr/local/bin/$(BINARY_NAME)

# Tidy go modules
mod-tidy:
	@echo "Tidying go modules..."
	go mod tidy

# Update dependencies
mod-update:
	@echo "Updating dependencies..."
	go get -u ./...
	go mod tidy

# Test variables
TEST ?= combined
TEST_DIR = tests/$(TEST)

# Build test container image
test-build-image:
	@echo "Building test container image with speedtest-cli..."
	@cd tests && docker build -t brakebear-test:latest .

# Start specific test scenario
test-up:
	@if [ ! -d "$(TEST_DIR)" ]; then \
		echo "Test scenario '$(TEST)' not found. Available: bandwidth-limit, high-latency, packet-loss, combined, unlimited"; \
		exit 1; \
	fi
	@echo "Starting test scenario: $(TEST)"
	@cd $(TEST_DIR) && (docker compose up -d || docker-compose up -d)

# Stop specific test scenario
test-down:
	@if [ ! -d "$(TEST_DIR)" ]; then \
		echo "Test scenario '$(TEST)' not found"; \
		exit 1; \
	fi
	@echo "Stopping test scenario: $(TEST)"
	@cd $(TEST_DIR) && (docker compose down || docker-compose down)

# Start all test scenarios
test-up-all:
	@for dir in tests/*/; do \
		if [ -f "$$dir/docker-compose.yml" ]; then \
			echo "Starting $$(basename $$dir)..."; \
			cd "$$dir" && (docker compose up -d || docker-compose up -d); \
			cd - > /dev/null; \
		fi; \
	done

# Stop all test scenarios
test-down-all:
	@for dir in tests/*/; do \
		if [ -f "$$dir/docker-compose.yml" ]; then \
			echo "Stopping $$(basename $$dir)..."; \
			cd "$$dir" && (docker compose down || docker-compose down); \
			cd - > /dev/null; \
		fi; \
	done

# Clean up test environment
test-cleanup: test-down-all
	@echo "Cleaning up test environment..."
	@docker network rm brakebear-test 2>/dev/null || true
	@docker rmi brakebear-test:latest 2>/dev/null || true

# Run test script for specific test scenario
test-script:
	@if [ ! -d "$(TEST_DIR)" ]; then \
		echo "Test scenario '$(TEST)' not found. Available: bandwidth-limit, high-latency, packet-loss, combined, unlimited"; \
		exit 1; \
	fi
	@if [ ! -f "$(TEST_DIR)/test.sh" ]; then \
		echo "Test script not found for scenario: $(TEST)"; \
		exit 1; \
	fi
	@echo "Running test script for scenario: $(TEST)"
	@cd $(TEST_DIR) && ./test.sh

# Run BrakeBear with specific test configuration
test-run-brakebear: build-dev
	@if [ ! -f "$(TEST_DIR)/brakebear.yaml" ]; then \
		echo "Config not found for test: $(TEST)"; \
		exit 1; \
	fi
	@echo "Running BrakeBear with test scenario: $(TEST)"
	@echo "Note: This requires root privileges for network operations"
	@echo "Press Ctrl+C to stop"
	sudo ./$(BINARY_NAME) run --config $(TEST_DIR)/brakebear.yaml

# Run full integration test suite
test-integration: test-build-image build-dev
	@echo "Running integration tests..."
	@set -e; \
	make test-up TEST=combined; \
	echo "Starting BrakeBear in background..."; \
	sudo ./$(BINARY_NAME) run --config tests/combined/brakebear.yaml & \
	BRAKEBEAR_PID=$$!; \
	echo "BrakeBear PID: $$BRAKEBEAR_PID"; \
	sleep 5; \
	echo "Running test script..."; \
	if make test-script TEST=combined; then \
		echo "Integration tests passed"; \
		RESULT=0; \
	else \
		echo "Integration tests failed"; \
		RESULT=1; \
	fi; \
	echo "Cleaning up BrakeBear process..."; \
	kill $$BRAKEBEAR_PID 2>/dev/null || true; \
	sleep 2; \
	echo "Cleaning up test containers..."; \
	make test-down-all; \
	exit $$RESULT


# Docker test (requires Docker to be running)
docker-test:
	@echo "Running Docker connectivity test..."
	@docker info >/dev/null 2>&1 || (echo "Docker is not running or accessible" && exit 1)
	@echo "Docker is accessible"

# OrbStack development VM management
orbstack-dev:
	@./.hack/orbstack.sh

orbstack-dev-clean:
	@./.hack/orbstack.sh cleanup

# Show help
help:
	@echo "BrakeBear Makefile Help"
	@echo ""
	@echo "Build Targets:"
	@echo "  build        Build the application (optimized)"
	@echo "  build-dev    Build for development (faster)"
	@echo "  clean        Clean build artifacts"
	@echo "  install      Install binary to /usr/local/bin"
	@echo "  uninstall    Remove binary from /usr/local/bin"
	@echo ""
	@echo "Code Quality:"
	@echo "  test         Run tests with race detector"
	@echo "  test-coverage Run tests with coverage report"
	@echo "  bench        Run benchmarks"
	@echo "  lint         Run golangci-lint"
	@echo "  fmt          Format code with go fmt"
	@echo "  vet          Run go vet"
	@echo "  check        Run all quality checks"
	@echo ""
	@echo "Dependencies:"
	@echo "  mod-tidy     Tidy go modules"
	@echo "  mod-update   Update all dependencies"
	@echo ""
	@echo "Testing:"
	@echo "  test-build-image Build test container image with tools"
	@echo "  test-integration Run full integration test suite"
	@echo "  test-up          Start test scenario (TEST=bandwidth-limit|high-latency|packet-loss|combined|unlimited)"
	@echo "  test-down        Stop test scenario"
	@echo "  test-up-all      Start all test scenarios"
	@echo "  test-down-all    Stop all test scenarios"
	@echo "  test-cleanup     Clean up all test containers and images"
	@echo "  test-run-brakebear Run BrakeBear with test config (TEST=scenario)"
	@echo "  test-script         Run test script for scenario (TEST=scenario)"
	@echo "  docker-test      Test Docker connectivity"
	@echo ""
	@echo "Test Usage Examples:"
	@echo "  make test-up TEST=bandwidth-limit   # Start bandwidth limit test"
	@echo "  make test-up TEST=combined          # Start combined test (default)"
	@echo "  make test-script TEST=bandwidth-limit      # Run bandwidth limit test script"
	@echo "  make test-run-brakebear TEST=high-latency # Run BrakeBear with latency config"
	@echo ""
	@echo "Development:"
	@echo "  orbstack-dev      Create OrbStack development VM"
	@echo "  orbstack-dev-clean Remove OrbStack development VM"
	@echo ""
	@echo "Documentation:"
	@echo "  help         Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  VERSION      Set build version (default: git tag/dev)"
	@echo "  COMMIT       Set build commit (default: git commit)"
	@echo "  BUILD_TIME   Set build time (default: current time)"

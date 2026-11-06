.PHONY: help build test test-unit test-integration test-coverage lint fmt vet clean install test-race build-all pre-commit-install pre-commit-run pre-commit-update

# Default target
.DEFAULT_GOAL := help

# Binary name and output directory
BINARY_NAME := ykgpg
BIN_DIR := bin
CMD_PATH := ./cmd/ykgpg

# Colors for output
CYAN := \033[0;36m
GREEN := \033[0;32m
YELLOW := \033[0;33m
NC := \033[0m # No Color

## help: Show this help message
help:
	@echo "$(CYAN)YubiKey GPG Manager - Makefile Commands$(NC)"
	@echo ""
	@echo "$(GREEN)Build Commands:$(NC)"
	@echo "  make build          - Build the binary (output: $(BIN_DIR)/$(BINARY_NAME))"
	@echo "  make build-all      - Build for multiple platforms (Linux, macOS, Windows)"
	@echo "  make install        - Install to $$GOPATH/bin"
	@echo ""
	@echo "$(GREEN)Test Commands:$(NC)"
	@echo "  make test           - Run all unit tests"
	@echo "  make test-unit      - Run unit tests only"
	@echo "  make test-integration - Run integration tests (requires GPG)"
	@echo "  make test-race      - Run tests with race detector"
	@echo "  make test-coverage  - Run tests with coverage report"
	@echo ""
	@echo "$(GREEN)Code Quality:$(NC)"
	@echo "  make fmt            - Format code with gofmt"
	@echo "  make vet            - Run go vet"
	@echo "  make lint           - Run golangci-lint (requires golangci-lint)"
	@echo ""
	@echo "$(GREEN)Pre-commit Commands:$(NC)"
	@echo "  make pre-commit-install - Install pre-commit hooks"
	@echo "  make pre-commit-run     - Run pre-commit hooks on all files"
	@echo "  make pre-commit-update  - Update pre-commit hooks"
	@echo ""
	@echo "$(GREEN)Utility Commands:$(NC)"
	@echo "  make clean          - Remove build artifacts"
	@echo "  make deps           - Download dependencies"
	@echo "  make deps-update    - Update dependencies"

## build: Build the binary
build:
	@echo "$(CYAN)Building $(BINARY_NAME)...$(NC)"
	@mkdir -p $(BIN_DIR)
	@go build -o $(BIN_DIR)/$(BINARY_NAME) $(CMD_PATH)
	@echo "$(GREEN)✓ Build complete: $(BIN_DIR)/$(BINARY_NAME)$(NC)"

## test: Run all unit tests
test: test-unit

## test-unit: Run unit tests only
test-unit:
	@echo "$(CYAN)Running unit tests...$(NC)"
	@go test -v ./...

## test-integration: Run integration tests (requires GPG)
test-integration:
	@echo "$(CYAN)Running integration tests...$(NC)"
	@echo "$(YELLOW)Note: This requires GPG to be installed and optionally a YubiKey$(NC)"
	@go test -tags=integration -v ./...

## test-coverage: Run tests with coverage report
test-coverage:
	@echo "$(CYAN)Running tests with coverage...$(NC)"
	@go test -coverprofile=coverage.out -covermode=atomic ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)✓ Coverage report generated: coverage.html$(NC)"
	@echo "$(CYAN)Coverage summary:$(NC)"
	@go tool cover -func=coverage.out | tail -1

## test-coverage-codecov: Generate coverage file for Codecov
test-coverage-codecov:
	@echo "$(CYAN)Generating coverage for Codecov...$(NC)"
	@go test -coverprofile=coverage.txt -covermode=atomic ./...
	@echo "$(GREEN)✓ Coverage file generated: coverage.txt$(NC)"
	@echo "$(CYAN)Coverage summary:$(NC)"
	@go tool cover -func=coverage.txt | tail -1

## test-race: Run tests with race detector
test-race:
	@echo "$(CYAN)Running tests with race detector...$(NC)"
	@go test -race ./...

## fmt: Format code with gofmt
fmt:
	@echo "$(CYAN)Formatting code...$(NC)"
	@go fmt ./...
	@echo "$(GREEN)✓ Code formatted$(NC)"

## vet: Run go vet
vet:
	@echo "$(CYAN)Running go vet...$(NC)"
	@go vet ./...
	@echo "$(GREEN)✓ go vet passed$(NC)"

## lint: Run golangci-lint (requires golangci-lint to be installed)
lint:
	@echo "$(CYAN)Running golangci-lint...$(NC)"
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "$(YELLOW)Warning: golangci-lint not found. Install with:$(NC)"; \
		echo "  brew install golangci-lint  # macOS"; \
		echo "  or visit https://golangci-lint.run/usage/install/"; \
		exit 1; \
	fi
	@golangci-lint run ./...

## clean: Remove build artifacts
clean:
	@echo "$(CYAN)Cleaning build artifacts...$(NC)"
	@rm -rf $(BIN_DIR)
	@rm -f coverage.out coverage.html
	@echo "$(GREEN)✓ Clean complete$(NC)"

## install: Install to $GOPATH/bin
install:
	@echo "$(CYAN)Installing $(BINARY_NAME) to $$GOPATH/bin...$(NC)"
	@go install $(CMD_PATH)
	@echo "$(GREEN)✓ Installed to $$GOPATH/bin/$(BINARY_NAME)$(NC)"

## deps: Download dependencies
deps:
	@echo "$(CYAN)Downloading dependencies...$(NC)"
	@go mod download
	@go mod tidy
	@echo "$(GREEN)✓ Dependencies downloaded$(NC)"

## deps-update: Update dependencies
deps-update:
	@echo "$(CYAN)Updating dependencies...$(NC)"
	@go get -u ./...
	@go mod tidy
	@echo "$(GREEN)✓ Dependencies updated$(NC)"

## build-all: Build for multiple platforms
build-all:
	@echo "$(CYAN)Building for multiple platforms...$(NC)"
	@mkdir -p $(BIN_DIR)
	@echo "$(CYAN)Building for Linux (amd64)...$(NC)"
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BIN_DIR)/$(BINARY_NAME)-linux-amd64 $(CMD_PATH)
	@echo "$(CYAN)Building for macOS (amd64)...$(NC)"
	@CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o $(BIN_DIR)/$(BINARY_NAME)-darwin-amd64 $(CMD_PATH)
	@echo "$(CYAN)Building for macOS (arm64)...$(NC)"
	@CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o $(BIN_DIR)/$(BINARY_NAME)-darwin-arm64 $(CMD_PATH)
	@echo "$(CYAN)Building for Windows (amd64)...$(NC)"
	@CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o $(BIN_DIR)/$(BINARY_NAME)-windows-amd64.exe $(CMD_PATH)
	@echo "$(GREEN)✓ Multi-platform build complete$(NC)"
	@ls -lh $(BIN_DIR)/

## pre-commit-install: Install pre-commit hooks
pre-commit-install:
	@echo "$(CYAN)Installing pre-commit hooks...$(NC)"
	@if ! command -v pre-commit >/dev/null 2>&1; then \
		echo "$(YELLOW)pre-commit not found. Installing...$(NC)"; \
		echo "$(YELLOW)Install with one of:$(NC)"; \
		echo "  brew install pre-commit  # macOS"; \
		echo "  pip install pre-commit  # Python"; \
		echo "  or visit https://pre-commit.com/#installation"; \
		exit 1; \
	fi
	@pre-commit install
	@pre-commit install --hook-type commit-msg
	@echo "$(GREEN)✓ Pre-commit hooks installed$(NC)"
	@echo "$(CYAN)Hooks will run automatically on git commit$(NC)"

## pre-commit-run: Run pre-commit hooks on all files
pre-commit-run:
	@echo "$(CYAN)Running pre-commit hooks on all files...$(NC)"
	@if ! command -v pre-commit >/dev/null 2>&1; then \
		echo "$(YELLOW)pre-commit not found. Run 'make pre-commit-install' first$(NC)"; \
		exit 1; \
	fi
	@echo "$(CYAN)Note: Pre-commit checks tracked/staged files.$(NC)"
	@echo "$(CYAN)Staging all files temporarily for checking...$(NC)"
	@git add -A || true
	@pre-commit run --all-files || true
	@echo ""
	@echo "$(GREEN)✓ Pre-commit check complete$(NC)"
	@echo "$(CYAN)Note: Files have been staged. Use 'git reset' to unstage if needed.$(NC)"

## pre-commit-update: Update pre-commit hooks to latest versions
pre-commit-update:
	@echo "$(CYAN)Updating pre-commit hooks...$(NC)"
	@if ! command -v pre-commit >/dev/null 2>&1; then \
		echo "$(YELLOW)pre-commit not found. Run 'make pre-commit-install' first$(NC)"; \
		exit 1; \
	fi
	@pre-commit autoupdate
	@echo "$(GREEN)✓ Pre-commit hooks updated$(NC)"

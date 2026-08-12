
.PHONY: help install uninstall test test-desktop check clean dev-setup shellcheck validate

INSTALL_DIR = /opt/lsmf
CONFIG_DIR = /etc/lsmf
BIN_LINK = /usr/local/bin/lsmf

help:
	@echo "Linux Security Management Framework (LSMF) - Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  make install        Install LSMF to system"
	@echo "  make uninstall      Uninstall LSMF from system"
	@echo "  make test           Run all tests"
	@echo "  make test-desktop   Run read-only desktop service tests"
	@echo "  make check          Run ShellCheck on all scripts"
	@echo "  make validate       Validate configuration files"
	@echo "  make clean          Clean temporary files"
	@echo "  make dev-setup      Set up development environment"
	@echo "  make shellcheck     Run ShellCheck with strict settings"
	@echo "  make help           Show this help message"

install:
	@echo "Installing LSMF..."
	@bash scripts/install.sh

uninstall:
	@echo "Uninstalling LSMF..."
	@bash scripts/uninstall.sh

test:
	@echo "Running tests..."
	@if [ -d tests ]; then \
		bash tests/run_tests.sh; \
	else \
		echo "No tests directory found"; \
	fi

test-desktop:
	@echo "Running desktop service tests..."
	@python3 -m unittest tests.test_desktop_services
	@python3 -m py_compile desktop/services.py desktop/main.py

check: shellcheck

shellcheck:
	@echo "Running ShellCheck..."
	@if command -v shellcheck >/dev/null 2>&1; then \
		find src -name "*.sh" -type f -exec shellcheck {} + ; \
		shellcheck src/lsmf; \
		shellcheck scripts/*.sh; \
		echo "ShellCheck passed!"; \
	else \
		echo "ShellCheck not installed. Install with: apt install shellcheck"; \
		exit 1; \
	fi

validate:
	@echo "Validating configuration files..."
	@bash -n config/lsmf.conf
	@find config/profiles -name "*.conf" -type f -exec bash -n {} \;
	@echo "Configuration files validated!"

clean:
	@echo "Cleaning temporary files..."
	@find . -name "*.tmp" -delete
	@find . -name "*.bak" -delete
	@find . -name "*~" -delete
	@echo "Clean complete!"

dev-setup:
	@echo "Setting up development environment..."
	@if ! command -v shellcheck >/dev/null 2>&1; then \
		echo "Installing ShellCheck..."; \
		if command -v apt-get >/dev/null 2>&1; then \
			sudo apt-get update && sudo apt-get install -y shellcheck; \
		elif command -v dnf >/dev/null 2>&1; then \
			sudo dnf install -y ShellCheck; \
		fi; \
	fi
	@if ! command -v dialog >/dev/null 2>&1; then \
		echo "Installing dialog..."; \
		if command -v apt-get >/dev/null 2>&1; then \
			sudo apt-get install -y dialog; \
		elif command -v dnf >/dev/null 2>&1; then \
			sudo dnf install -y dialog; \
		fi; \
	fi
	@echo "Development environment ready!"

dry-run:
	@echo "Running LSMF in dry-run mode..."
	@sudo bash src/lsmf -d harden

audit:
	@echo "Running security audit..."
	@sudo bash src/lsmf audit

run:
	@echo "Starting LSMF interactive menu..."
	@sudo bash src/lsmf ui

# fd0 build / test / lint helpers.
#
# Targets:
#   make build        — go install all binaries
#   make test         — go test ./... (unit + property + adversarial)
#   make integration  — run all tests/integration_*.sh
#   make lint         — go vet + semgrep rules (semgrep optional)
#   make all          — build + test + integration + lint

.PHONY: build test integration lint vet semgrep threat-coverage all

build:
	go install ./...

test:
	go test ./... -count=1 -timeout 180s

integration:
	bash tests/run_isolated_integration.sh

vet:
	go vet ./...

# golangci-lint covers the bug classes already observed in past
# review rounds (errcheck, bodyclose, gosec, staticcheck, unused).
# Config lives at .golangci.yml; install via `brew install
# golangci-lint` or per https://golangci-lint.run/install.
golangci:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed; skipping (brew install golangci-lint)"; \
	fi

# semgrep rules from tools/semgrep/. Skipped silently when semgrep
# isn't installed (CI installs it; local dev can opt in).
semgrep:
	@if command -v semgrep >/dev/null 2>&1; then \
		bash tools/semgrep/run.sh; \
	else \
		echo "semgrep not installed; skipping (pip install semgrep)"; \
	fi

# threat-coverage walks THREATS.md and verifies every threat that
# requires a code annotation has at least one `// THREAT: Tnn`
# in non-test code, and that every annotation references a
# catalogued threat. Closes the doc-↔-code drift risk that
# THREATS.md §8 explicitly flags.
threat-coverage:
	@go run ./tools/threat-coverage

lint: vet golangci semgrep threat-coverage

all: build test integration lint

# fd0 build / test / lint helpers.
#
# Targets:
#   make build        — go install all binaries
#   make test         — go test ./... (unit + property + adversarial)
#   make integration  — run all tests/integration_*.sh
#   make lint         — go vet + semgrep rules (semgrep optional)
#   make all          — build + test + integration + lint

.PHONY: build test integration lint vet semgrep all

build:
	go install ./...

test:
	go test ./... -count=1 -timeout 180s

integration:
	@for f in tests/integration_*.sh; do \
		pkill -f fd0-server 2>/dev/null || true; \
		pkill -f fd0-agent 2>/dev/null || true; \
		pkill -f fd0-witness 2>/dev/null || true; \
		sleep 0.3; \
		echo "=== $$f ==="; \
		bash "$$f" || exit 1; \
	done

vet:
	go vet ./...

# semgrep rules from tools/semgrep/. Skipped silently when semgrep
# isn't installed (CI installs it; local dev can opt in).
semgrep:
	@if command -v semgrep >/dev/null 2>&1; then \
		bash tools/semgrep/run.sh; \
	else \
		echo "semgrep not installed; skipping (pip install semgrep)"; \
	fi

lint: vet semgrep

all: build test integration lint

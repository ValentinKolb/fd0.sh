#!/usr/bin/env bash
# Run all fd0 semgrep rules against the repo.
# Exits non-zero on any ERROR-level finding (warnings allowed).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

if ! command -v semgrep >/dev/null 2>&1; then
    cat <<'EOF' >&2
semgrep not installed. Install with:
    pip install semgrep
or:
    brew install semgrep
Then re-run this script.
EOF
    exit 2
fi

cd "$REPO_ROOT"
exec semgrep \
    --config "$SCRIPT_DIR/rules/" \
    --error \
    --metrics=off \
    --quiet \
    --exclude tools/semgrep \
    --exclude vendor \
    .

#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
failed=0

for workflow in "$root"/.github/workflows/release*.yml; do
    while IFS= read -r reference; do
        case "$reference" in
            *@????????????????????????????????????????) ;;
            *)
                printf 'mutable action reference in %s: %s\n' "$workflow" "$reference" >&2
                failed=1
                ;;
        esac
    done <<EOF
$(sed -n 's/^[[:space:]]*-*[[:space:]]*uses:[[:space:]]*\([^[:space:]#]*\).*/\1/p' "$workflow")
EOF
done

if grep -R -nE 'version:[[:space:]]*latest|goreleaser.*@v[0-9]+([[:space:]#]|$)' \
    "$root/.github/workflows"/release*.yml >/dev/null; then
    printf 'mutable release tool version found\n' >&2
    failed=1
fi

[ "$failed" -eq 0 ]

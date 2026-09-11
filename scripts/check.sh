#!/usr/bin/env bash
# Runs the same checks as CI, locally, before pushing.
#
#   ./scripts/check.sh
#
# Stops at the first failure.
set -euo pipefail

cd "$(dirname "$0")/.."

step() { printf '\n=== %s %s\n' "$1" "$(printf '=%.0s' $(seq 1 $((60 - ${#1}))))"; }

step "Rule syntax"
sigma check rules/

step "Go vet"
go vet ./...

# Mirrors CI: a missing dataset or binary becomes a failure, not a skip.
step "Rule tests"
RASTRO_REQUIRE_TOOLS=1 go test ./... -v

step "About to commit"
git status --short

if git diff --cached --name-only | grep -E '\.(exe|csv)$|^datasets/|^tools/' ; then
    printf '\nWARNING: the staged paths above look like build output or external data.\n'
    printf 'Unstage them with: git restore --staged <path>\n'
    exit 1
fi

printf '\nAll checks passed.\n'

#!/usr/bin/env bash
# check-no-plan-taxonomy.sh
#
# Pre-commit hook: prevents internal plan taxonomy tokens from leaking into
# tracked artifacts (commits, PR bodies, docs, code comments).
#
# Enforces .claude/rules/development-rules.md "Plan-Taxonomy Exposure" rule.
# Runs against staged content only (git diff --cached).
#
# Forbidden tokens:
#   - Slice identifiers: slice-a, slice-b, Slice A, Slice B, ...
#   - Phase identifiers: phase-1, phase-01, Phase 1, Phase 2, ...
#   - Red-team labels: red-team-v1, red-team A1, ...

set -euo pipefail

PATTERN='(slice-[a-z][^a-z]|Slice [A-Z][^A-Z]|phase-?[0-9]+|Phase [0-9]+|red-team-v[0-9]|red-team [A-Z][0-9])'

# Get list of staged files (null-delimited for safety with special chars)
STAGED=$(git diff --cached --name-only -z 2>/dev/null)

if [ -z "$STAGED" ]; then
    exit 0
fi

# Search staged file contents for forbidden tokens
MATCHES=$(echo "$STAGED" | xargs -0 grep -nE "$PATTERN" 2>/dev/null || true)

if [ -n "$MATCHES" ]; then
    echo "VIOLATION: plan taxonomy tokens found in staged content."
    echo "See .claude/rules/development-rules.md 'Plan-Taxonomy Exposure' for allowed substitutions."
    echo ""
    echo "$MATCHES"
    exit 1
fi

exit 0

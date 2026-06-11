#!/usr/bin/env bash
# scripts/verify_coff.sh — verify COFF artifacts in dist/.
# Checks: valid object header, `go` (or `_go`) symbol exported,
#         no leaked sensitive strings.
# Author: Dani <daniagungg@gmail.com>
set -euo pipefail

LEAK_REGEX='ntopenprocesstoken|cocreateinstance|software\\microsoft\\windows\\currentversion\\run|sedebugprivilege|inline ?execute ?ex|kuser_shared_data'

LLVM_AVAILABLE=1
if ! command -v llvm-objdump >/dev/null 2>&1 || ! command -v llvm-readobj >/dev/null 2>&1; then
    echo "WARN: llvm-objdump/readobj not in PATH; skipping COFF structure + symbol checks (install llvm via brew to enable)" >&2
    LLVM_AVAILABLE=0
fi

fail=0
count=0
for f in dist/*.o; do
    [[ -e "$f" ]] || continue
    count=$((count + 1))

    if [[ "$LLVM_AVAILABLE" -eq 1 ]]; then
        if ! llvm-objdump -h "$f" >/dev/null 2>&1; then
            echo "FAIL: $f — invalid object header" >&2
            fail=1; continue
        fi
        if ! llvm-readobj --symbols "$f" 2>/dev/null | grep -qE 'Name: _?go$'; then
            echo "FAIL: $f — missing 'go' export symbol" >&2
            fail=1
        fi
    fi

    leaked=$(strings "$f" | grep -ciE "$LEAK_REGEX" || true)
    if [[ "$leaked" -gt 0 ]]; then
        echo "FAIL: $f — leaked $leaked sensitive strings" >&2
        strings "$f" | grep -iE "$LEAK_REGEX" | head -5 >&2
        fail=1
    fi
done

if [[ "$count" -eq 0 ]]; then
    echo "WARN: no .o files in dist/" >&2; exit 0
fi
[[ "$fail" -eq 0 ]] && echo "✓ $count COFF artifacts verified" || exit 1

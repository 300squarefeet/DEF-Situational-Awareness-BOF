#!/usr/bin/env bash
# scripts/build_all.sh — build every Phase-1+ BOF crate.
# Tolerates per-arch failures so x64-only BOFs don't abort the whole run.
# Author: Dani <daniagungg@gmail.com>
# Compatible with bash 3.2+ (macOS default).
set -o pipefail   # NB: no -e so we can continue on per-arch failures

mkdir -p dist

# Collect crate names into an array (bash 3.2-compatible: while-read loop).
CRATES=()
while IFS= read -r crate; do
    CRATES+=("$crate")
done < <(cargo metadata --no-deps --format-version 1 \
    | jq -r '.packages[] | select(.name != "common") | .name' \
    | sort -u)

if [[ "${#CRATES[@]}" -eq 0 ]]; then
    echo "ERROR: no BOF crates found in workspace (only 'common' present)" >&2
    exit 1
fi

echo "==> Building ${#CRATES[@]} crates"
total_ok=0
total_fail=0
for crate in "${CRATES[@]}"; do
    echo "---"
    echo "Building: $crate"
    if bash scripts/build_one.sh "$crate"; then
        total_ok=$((total_ok + 1))
    else
        # build_one.sh exits non-zero if EITHER arch fails. We accept this:
        # the per-arch artifacts that succeeded are still in dist/. Count as
        # partial success if at least the x64 file exists.
        if [[ -f "dist/${crate}.x64.o" ]]; then
            echo "WARN: $crate — x86 failed but x64 succeeded; continuing"
            total_ok=$((total_ok + 1))
        else
            echo "FAIL: $crate — no artifacts produced"
            total_fail=$((total_fail + 1))
        fi
    fi
done

echo "==> Building inline-execute-ex-opsec fork (bofx)"
if [[ -d tools/inline-execute-ex-opsec ]]; then
    if make -C tools/inline-execute-ex-opsec CROSS=x86_64-w64-mingw32- ARCH=x64 >/dev/null 2>&1; then
        cp tools/inline-execute-ex-opsec/build/bofx.x64.o dist/
        echo "  ✓ bofx.x64.o"
    else
        echo "  WARN: bofx x64 build failed"
    fi
    if make -C tools/inline-execute-ex-opsec CROSS=i686-w64-mingw32- ARCH=x86 >/dev/null 2>&1; then
        cp tools/inline-execute-ex-opsec/build/bofx.x86.o dist/
        echo "  ✓ bofx.x86.o"
    else
        echo "  WARN: bofx x86 build failed"
    fi
fi

echo "==> Verifying"
bash scripts/verify_coff.sh || true

echo "==> Generating manifest"
python3 scripts/gen_manifest.py > dist/manifest.json
cat dist/manifest.json

echo
echo "==> Summary: $total_ok succeeded ($total_fail failed) — $(ls dist/*.o | wc -l | tr -d ' ') .o artifacts"
[[ "$total_fail" -eq 0 ]] || exit 1
echo "==> ✓ build_all complete"

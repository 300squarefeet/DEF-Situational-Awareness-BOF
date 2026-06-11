<!--
SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
SPDX-License-Identifier: MIT
-->

# Upstream drop-in checklist

This fork ships a minimal OPSEC scaffolding (`src/bof.cpp`, `src/obfstr.h`,
`aggressor/bofx.cna`, `Makefile`). To produce a fully-functional `bofx`
loader, drop the upstream sources into `src/` and apply the patch
checklist below.

## 0. Fetch upstream

```bash
cd /tmp
git clone --depth 1 https://github.com/0xTriboulet/InlineExecuteEx
cp /tmp/InlineExecuteEx/BOF-Template/{bof.cpp,api_table.h,beacon.h,beacon_gate.h,sleepmask.h,common.h,coff.h,bofpe.h,bof_helpers.h} \
   tools/inline-execute-ex-opsec/src/
```

The upstream `bof.cpp` will overwrite the OPSEC scaffolding. That's
intended — apply the patch checklist below.

## 1. Re-apply OPSEC patches in `src/bof.cpp`

```cpp
#include "obfstr.h"     // add at top
```

Replace string literal occurrences inside the COFF/PE parser:

| Upstream literal | Replace with |
|---|---|
| `".text"` | `OBF(".text")` |
| `".data"` | `OBF(".data")` |
| `".rdata"` | `OBF(".rdata")` |
| `".pdata"` | `OBF(".pdata")` |
| `".bss"` | `OBF(".bss")` |
| `"go"` | `OBF("go")` |
| `"_go"` | `OBF("_go")` |
| `"MSVCRT"` | `OBF("MSVCRT")` |
| `"ntdll"` | `OBF("ntdll")` |
| `"kernel32"` | `OBF("kernel32")` |

Collapse every `BeaconPrintf(CALLBACK_ERROR, "...long string...");` to
`bofx_err(BofxErr::<code>);` per the enum in the scaffolding.

Wrap `runBof` and `runPE` so the `BofxScope` RAII fires on every return
path (Modification #8). The scaffolding's `go()` shows the pattern.

## 2. Apply `--strip-all` + visibility flags (already in Makefile)

Nothing to do — the Makefile already sets `-fvisibility=hidden`,
`-fno-asynchronous-unwind-tables`, and `LDFLAGS += --strip-all`.

## 3. Aggressor (already done)

`aggressor/bofx.cna` is already OPSEC-patched. The upstream
`inline-execute-ex.cna` is intentionally not vendored — replace any
mention with `bofx.cna`.

## 4. Build

```bash
make CROSS=x86_64-w64-mingw32- ARCH=x64
```

Verify no plaintext leaks:

```bash
strings build/bofx.x64.o | grep -E '\.text|\.data|MSVCRT|EXPERIMENTAL|BOF\+' || echo "OK: no plaintext leaks"
```

## 5. Load in Cobalt Strike

See `README.md` § Usage.

## Notes

- `API_TABLE` layout in `api_table.h` MUST stay byte-for-byte identical
  to upstream so PIC BOFs that depend on the vtable still load.
- The COFF parser in `coff.h` and PE parser in `bofpe.h` should NOT be
  modified beyond the literal-replacement table above. The parsers are
  well-tested; changes there risk breaking COFF compatibility.

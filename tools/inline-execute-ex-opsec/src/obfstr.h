// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//
// obfstr.h — compile-time XOR string obfuscation for the InlineExecuteEx
// OPSEC fork. Sensitive string literals (".text", ".data", "go", "MSVCRT",
// etc.) are encrypted at compile time, then decrypted on the stack at the
// use-site so the plaintext never appears in .rdata.
//
// Author: Dani <daniagungg@gmail.com>
// Upstream-context: github.com/0xTriboulet/InlineExecuteEx (MIT)

#ifndef GHOSTCAM_BOFX_OBFSTR_H
#define GHOSTCAM_BOFX_OBFSTR_H

#include <cstddef>

namespace stk {

    // XOR key derived from index — varies per character so a flat key search
    // (single-byte XOR brute force) doesn't trivially recover the literal.
    constexpr char x(char c, int i) {
        return static_cast<char>(c ^ (0xAA + (i & 0x3F)));
    }

    template <size_t N>
    struct obf_str {
        char data[N];
        constexpr obf_str(const char (&s)[N]) : data{} {
            for (size_t i = 0; i < N; ++i) {
                data[i] = x(s[i], static_cast<int>(i));
            }
        }
    };

} // namespace stk

// OBF(s): returns a const char* to a stack buffer holding the decrypted
// form of s. The encrypted form lives in .rdata; the plaintext only
// exists transiently on the stack while the BOF runs. The buffer is a
// non-TLS automatic to avoid emutls symbol bloat under MinGW (BOFs are
// single-threaded inside Beacon, so per-thread storage is unnecessary).
//
// Note: the lifetime of the returned pointer is the enclosing block.
// Copy or consume immediately — do NOT cache the pointer across calls.
//
// Usage:
//     const char* sec = OBF(".text");
//     if (strcmp(name, sec) == 0) { ... }
#define OBF(s)                                                                \
    ([]() -> const char* {                                                    \
        static constexpr auto __o = stk::obf_str<sizeof(s)>(s);               \
        static char __buf[sizeof(s)];                                         \
        for (size_t __i = 0; __i < sizeof(s); ++__i) {                        \
            __buf[__i] = stk::x(__o.data[__i], static_cast<int>(__i));        \
        }                                                                     \
        return __buf;                                                         \
    }())

#endif // GHOSTCAM_BOFX_OBFSTR_H

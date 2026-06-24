#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
# SPDX-License-Identifier: MIT
#
# encrypt_bof.py — AES-128-CBC encrypt a COFF .o for the bofx-enc variant.
# Output format: "BOFXENC1" (8B) + IV (16B) + AES-128-CBC ciphertext (PKCS7 padded)
#
# Usage:
#   python3 encrypt_bof.py dist/whoami.x64.o --key <32-hex-char>
#   python3 encrypt_bof.py dist/whoami.x64.o  # generates random key
#
# The key must be compiled into the bofx loader:
#   make CROSS=x86_64-w64-mingw32- ARCH=x64 BOFX_KEY=<hex>

from __future__ import annotations
import argparse, os, sys, struct
from pathlib import Path

# Pure-Python AES-128 (no external deps)
SBOX = bytes([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
])
RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def _xtime(a): return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff

def _mix_col(col):
    t = col[0] ^ col[1] ^ col[2] ^ col[3]
    u = col[0]
    col[0] ^= _xtime(col[0] ^ col[1]) ^ t
    col[1] ^= _xtime(col[1] ^ col[2]) ^ t
    col[2] ^= _xtime(col[2] ^ col[3]) ^ t
    col[3] ^= _xtime(col[3] ^ u) ^ t

def _key_expansion(key: bytes) -> list[list[int]]:
    w = [list(key[i:i+4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        tmp = list(w[i-1])
        if i % 4 == 0:
            tmp = [SBOX[tmp[1]] ^ RCON[i//4-1], SBOX[tmp[2]], SBOX[tmp[3]], SBOX[tmp[0]]]
        w.append([w[i-4][j] ^ tmp[j] for j in range(4)])
    return w

def _aes_encrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    state = [list(block[i:i+4]) for i in range(0, 16, 4)]
    # Transpose to column-major
    s = [[state[j][i] for j in range(4)] for i in range(4)]
    # AddRoundKey 0
    for c in range(4):
        for r in range(4): s[c][r] ^= round_keys[c][r]
    for rnd in range(1, 11):
        # SubBytes
        for c in range(4):
            for r in range(4): s[c][r] = SBOX[s[c][r]]
        # ShiftRows
        for r in range(1, 4):
            row = [s[c][r] for c in range(4)]
            for c in range(4): s[c][r] = row[(c + r) % 4]
        # MixColumns (skip last round)
        if rnd < 10:
            for c in range(4): _mix_col(s[c])
        # AddRoundKey
        rk = round_keys[rnd*4:(rnd+1)*4]
        for c in range(4):
            for r in range(4): s[c][r] ^= rk[c][r]
    # Transpose back
    out = bytearray(16)
    for c in range(4):
        for r in range(4): out[c*4+r] = s[c][r]
    return bytes(out)

def aes128_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    # PKCS7 pad
    pad_len = 16 - (len(plaintext) % 16)
    plaintext += bytes([pad_len] * pad_len)
    rk = _key_expansion(key)
    ct = bytearray()
    prev = iv
    for i in range(0, len(plaintext), 16):
        block = bytes(plaintext[i+j] ^ prev[j] for j in range(16))
        enc = _aes_encrypt_block(block, rk)
        ct.extend(enc)
        prev = enc
    return bytes(ct)

def main() -> int:
    ap = argparse.ArgumentParser(description="AES-128-CBC encrypt a BOF .o for bofx-enc.")
    ap.add_argument("input", type=Path, help="Path to the COFF .o file.")
    ap.add_argument("-o", "--output", type=Path, default=None)
    ap.add_argument("--key", default=None, help="32-char hex AES-128 key (default: random).")
    args = ap.parse_args()

    if not args.input.exists():
        print(f"error: {args.input} not found", file=sys.stderr)
        return 2

    out = args.output or args.input.with_suffix(args.input.suffix + ".enc")
    plaintext = args.input.read_bytes()

    if args.key:
        key = bytes.fromhex(args.key)
        if len(key) != 16:
            print("error: key must be 32 hex chars (16 bytes)", file=sys.stderr)
            return 1
    else:
        key = os.urandom(16)

    iv = os.urandom(16)
    ciphertext = aes128_cbc_encrypt(key, iv, plaintext)

    # Output: BOFXENC1 + IV + ciphertext
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(b"BOFXENC1" + iv + ciphertext)

    print(f"key={key.hex()}")
    print(f"iv={iv.hex()}")
    print(f"input={args.input} ({len(plaintext)} bytes)")
    print(f"output={out} ({8 + 16 + len(ciphertext)} bytes)")
    return 0

if __name__ == "__main__":
    sys.exit(main())

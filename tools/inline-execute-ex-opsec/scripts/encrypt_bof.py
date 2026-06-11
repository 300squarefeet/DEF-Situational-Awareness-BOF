#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
# SPDX-License-Identifier: MIT
#
# encrypt_bof.py — AES-128-CBC encrypt a COFF .o for the bofx-enc variant.
#
# Author:   Dani <daniagungg@gmail.com>
# Status:   stub — deferred to Phase 7+. The bofx-enc loader variant is
#           not yet shipped; this script is a placeholder so the operator
#           workflow (`for o in dist/*.x64.o; do encrypt_bof.py "$o"; done`)
#           is ready when the loader lands.

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser(
        description="AES-128-CBC encrypt a BOF .o for the bofx-enc variant (Phase 7+ stub)."
    )
    ap.add_argument("input", type=Path, help="Path to the COFF .o file.")
    ap.add_argument("-o", "--output", type=Path, default=None,
                    help="Output .enc path (default: <input>.enc).")
    ap.add_argument("--key", default=None,
                    help="32-char hex AES-128 key. Default: env BOFX_ENC_KEY or random.")
    args = ap.parse_args()

    if not args.input.exists():
        print(f"error: input not found: {args.input}", file=sys.stderr)
        return 2

    out = args.output or args.input.with_suffix(args.input.suffix + ".enc")
    out.parent.mkdir(parents=True, exist_ok=True)

    print(
        "warning: bofx-enc variant is deferred to Phase 7+. This script is a stub.\n"
        f"         input  = {args.input}\n"
        f"         output = {out}\n"
        "         No encryption performed; copy your .o once the loader ships.",
        file=sys.stderr,
    )

    # Stub: emit a marker file so downstream scripts (smoke_test.sh) can
    # at least iterate the workflow without aborting.
    out.write_bytes(b"BOFXENC0\x00")
    return 0


if __name__ == "__main__":
    sys.exit(main())

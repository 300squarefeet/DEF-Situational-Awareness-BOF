# SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
# SPDX-License-Identifier: MIT
#
# tools/inline-execute-ex-opsec/Makefile — MinGW cross-build from macOS.
#
# Author:    Dani <daniagungg@gmail.com>
# Upstream:  github.com/0xTriboulet/InlineExecuteEx (MIT)
#
# Output: build/bofx.x64.o  (and build/bofx.x86.o for ARCH=x86)

CROSS ?= x86_64-w64-mingw32-
ARCH  ?= x64
NAME  ?= bofx

CXX     = $(CROSS)g++
LD      = $(CROSS)ld
OBJCOPY = $(CROSS)objcopy
STRIP   = $(CROSS)strip

SRC      = src/bof.cpp
OUT_DIR  = build
OUT      = $(OUT_DIR)/$(NAME).$(ARCH).o

# Modification #2: symbol-hiding + asynchronous-unwind-tables strip.
# Modification #5: error codes via -DOPSEC_FORK=1 enables release-only paths.
CXXFLAGS = -std=c++17 -Os -fno-exceptions -fno-rtti                            \
           -fvisibility=hidden -fvisibility-inlines-hidden                     \
           -fno-asynchronous-unwind-tables                                     \
           -fno-stack-protector -fno-ident                                     \
           -nostdlib -nodefaultlibs                                            \
           -DOPSEC_FORK=1 -DCMD_NAME=\"$(NAME)\"                               \
           -Isrc/

# `--strip-all` removes the symbol table; `-r` keeps it relocatable so
# Cobalt Strike's inline-execute can load it.
LDFLAGS = --strip-all

.PHONY: all clean print-config

all: $(OUT)

$(OUT): $(SRC) src/obfstr.h | $(OUT_DIR)
	$(CXX) $(CXXFLAGS) -c $(SRC) -o $(OUT)
	$(STRIP) --strip-unneeded $(OUT) || true
	@echo "==> built $(OUT)"
	@echo "==> symbol count: $$($(CROSS)nm $(OUT) 2>/dev/null | wc -l | tr -d ' ')"

$(OUT_DIR):
	@mkdir -p $(OUT_DIR)

print-config:
	@echo "CROSS    = $(CROSS)"
	@echo "ARCH     = $(ARCH)"
	@echo "NAME     = $(NAME)"
	@echo "CXX      = $(CXX)"
	@echo "OUT      = $(OUT)"
	@echo "CXXFLAGS = $(CXXFLAGS)"

clean:
	rm -rf $(OUT_DIR)

#!/usr/bin/env bash
# Copyright 2026 Edk2Fuzz Contributors. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# OSS-Fuzz build script for Edk2Fuzz.
set -eux

REPO_DIR="$SRC/edk2fuzz"
EDK2_DIR="$SRC/edk2"


make -j"$(nproc)" -C "$EDK2_DIR/BaseTools"

# Lowercase required
ln -sfn "$REPO_DIR" "$SRC/Edk2Fuzz"

export WORKSPACE="$REPO_DIR"
export EDK_TOOLS_PATH="$EDK2_DIR/BaseTools"
export PACKAGES_PATH="$EDK2_DIR:$SRC"

cd "$EDK2_DIR"

export PYTHON_COMMAND="${PYTHON_COMMAND:-python3}"
export CONF_PATH="${CONF_PATH:-}"
source edksetup.sh BaseTools
cp -f "$REPO_DIR/Conf/build_rule.txt" "$EDK2_DIR/Conf/build_rule.txt"
cp -f "$REPO_DIR/Conf/tools_def.txt"  "$EDK2_DIR/Conf/tools_def.txt"

export AFL_USE_ASAN=1
export AFL_BIN="$SRC/aflplusplus/"

build_target() {
    local harness="$1" inf="$2" out_name="$3" seed_dir="$4"

    cd "$REPO_DIR"
    build \
        -p Edk2Fuzz.dsc \
        -m "$inf" \
        -a X64 \
        -t AFLCLANG \
        -b DEBUG \
        -D EDK2_ROOT="$EDK2_DIR"

    cp "$REPO_DIR/Build/Edk2FuzzPkg/DEBUG_AFLCLANG/X64/$harness" "$OUT/$out_name"

    if [ -d "$seed_dir" ]; then
        (cd "$seed_dir" && zip -r "$OUT/${out_name}_seed_corpus.zip" .)
    else
        echo "WARNING: seed corpus dir not found: $seed_dir" >&2
    fi
}

build_target \
    "TestDhcp6Driver" \
    "FuzzHarness/NetworkPkg/Dhcp6Dxe/TestDhcp6Driver/TestDhcp6Driver.inf" \
    "test_dhcp6_driver" \
    "$REPO_DIR/Seed/NetworkPkg/Dhcp6Dxe/TestDhcp6Driver/Raw"

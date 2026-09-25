# Copyright 2026 Edk2Metis Contributors. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause-Patent
FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        nasm \
        uuid-dev \
        iasl \
        python3 \
        python3-distutils \
        python-is-python3 \
        bison \
        flex \
        bc \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch master https://github.com/tianocore/edk2.git $SRC/edk2 \
 && git -C $SRC/edk2 submodule update --init --depth 1

RUN git clone --depth 1 https://github.com/TianoShield/edk2-metis.git $SRC/edk2-metis

WORKDIR $SRC/edk2-metis
COPY build.sh $SRC/

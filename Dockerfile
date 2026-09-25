# Dockerfile — Ubuntu 22.04 image ready to build EDK2 + Edk2Metis with dynamic UID/GID
FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive
ARG USERNAME=builder

# System packages needed to build edk2, AFL++, and run host-based fuzzing
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      software-properties-common apt-utils apt-transport-https ca-certificates \
      wget curl git unzip xz-utils file sudo gosu locales gnupg \
      build-essential pkg-config bear ninja-build cmake automake \
      python3 python3-pip python3-venv python3-dev python3-setuptools \
      python3-distutils python-is-python3 \
      clang llvm clang-tools llvm-dev lld \
      gcc-11-plugin-dev libstdc++-11-dev \
      uuid-dev libssl-dev libelf-dev libncurses-dev libjsoncpp-dev \
      libglib2.0-dev libpixman-1-dev libgtk-3-dev \
      nasm iasl acpica-tools u-boot-tools flex bison bc dosfstools \
      lcov gdb \
      iproute2 iputils-ping net-tools tcpdump dnsmasq \
      qemu-system-x86 qemu-utils \
      tmux openssh-client \
 && rm -rf /var/lib/apt/lists/*

# UTF-8 locale for GEF and other tools
RUN locale-gen en_US.UTF-8
ENV LANG=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8

# Default user (UID/GID rewritten at runtime by entrypoint)
RUN groupadd -g 1000 ${USERNAME} \
 && useradd -m -u 1000 -g 1000 -s /bin/bash ${USERNAME} \
 && echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${USERNAME} \
 && chmod 0440 /etc/sudoers.d/${USERNAME}

# GEF (best-effort)
RUN git clone --depth 1 https://github.com/hugsy/gef.git /tmp/gef 2>/dev/null \
 && su - ${USERNAME} -c "echo 'source /tmp/gef/gef.py' >> ~/.gdbinit" \
 || echo "Warning: GEF installation skipped."

# Entrypoint adjusts UID/GID and restores private prompt symlinks
RUN cat > /usr/local/bin/entrypoint.sh <<'ENTRYPOINT_EOF'
#!/bin/bash
set -e
USERNAME=builder
USER_UID=${HOST_UID:-1000}
USER_GID=${HOST_GID:-1000}

if [ "$(id -g ${USERNAME})" != "${USER_GID}" ]; then
    groupmod -g ${USER_GID} ${USERNAME} 2>/dev/null || true
fi
if [ "$(id -u ${USERNAME})" != "${USER_UID}" ]; then
    usermod -u ${USER_UID} ${USERNAME} 2>/dev/null || true
fi
chown -R ${USERNAME}:${USERNAME} /home/${USERNAME} 2>/dev/null || true
chmod 1777 /tmp 2>/dev/null || true

# Restore .claude / .github symlinks into the .private/ submodule
REPO_DIR=/home/${USERNAME}/edk2-metis_workspace/Edk2Metis
if [ -d "${REPO_DIR}/.git" ] || [ -f "${REPO_DIR}/.git" ]; then
    if [ -e "${REPO_DIR}/.private/.claude" ] && [ ! -e "${REPO_DIR}/.claude" ]; then
        gosu ${USERNAME} ln -sfn .private/.claude "${REPO_DIR}/.claude" 2>/dev/null || true
    fi
    if [ -e "${REPO_DIR}/.private/.github" ] && [ ! -e "${REPO_DIR}/.github" ]; then
        gosu ${USERNAME} ln -sfn .private/.github "${REPO_DIR}/.github" 2>/dev/null || true
    fi
fi

exec gosu ${USERNAME} "$@"
ENTRYPOINT_EOF
RUN chmod +x /usr/local/bin/entrypoint.sh

# Env: workspace = parent dir containing both `Edk2Metis/` (the repo) and resolves
# `Edk2Metis/Edk2Metis.dec` via PACKAGES_PATH.  Inside `Edk2Metis/` are the
# `edk2/` and `AFLplusplus/` submodules.
ENV USERNAME=${USERNAME}
ENV HOME=/home/${USERNAME}
ENV WORKSPACE_PARENT=/home/${USERNAME}/edk2-metis_workspace
ENV WORKSPACE=${WORKSPACE_PARENT}/Edk2Metis
ENV AFL_PATH=${WORKSPACE}/AFLplusplus
ENV EDK2_PATH=${WORKSPACE}/edk2
ENV PATH="${AFL_PATH}:${PATH}"

# Convenience init script — source to populate edk2 + AFL++ + edk2-metis env
RUN mkdir -p ${WORKSPACE} \
 && cat > ${HOME}/init_edk2-metis_env.sh <<'EOF'
#!/usr/bin/env bash
# Source this script to set up env for building EDK2 + Edk2Metis in this container.
export WORKSPACE_PARENT="$HOME/edk2-metis_workspace"
export WORKSPACE="$WORKSPACE_PARENT/Edk2Metis"
export EDK2_PATH="$WORKSPACE/edk2"
export AFL_PATH="$WORKSPACE/AFLplusplus"
export PACKAGES_PATH="$EDK2_PATH:$WORKSPACE_PARENT"
export EDK_TOOLS_PATH="$EDK2_PATH/BaseTools"
export PATH="$AFL_PATH:$PATH"
export CLANG_PATH="/usr/bin"
export ASAN_SYMBOLIZER_PATH="$CLANG_PATH/llvm-symbolizer"

echo "============================================"
echo "Edk2Metis Environment Setup"
echo "  WORKSPACE       = $WORKSPACE"
echo "  PACKAGES_PATH   = $PACKAGES_PATH"
echo "  EDK2_PATH       = $EDK2_PATH"
echo "  AFL_PATH        = $AFL_PATH"
echo "============================================"

# Build AFL++ if not already built
if [ -d "$AFL_PATH" ] && [ ! -x "$AFL_PATH/afl-gcc-fast" ]; then
    echo "Building AFL++..."
    make -j"$(nproc)" -C "$AFL_PATH" all
fi

# Build edk2 BaseTools if not already built
if [ -d "$EDK2_PATH" ] && [ ! -x "$EDK2_PATH/BaseTools/Source/C/bin/GenFw" ]; then
    echo "Building EDK2 BaseTools..."
    make -j"$(nproc)" -C "$EDK2_PATH/BaseTools"
fi

# edksetup
if [ -f "$EDK2_PATH/edksetup.sh" ]; then
    pushd "$EDK2_PATH" >/dev/null
    source edksetup.sh
    popd >/dev/null
fi

# Install Edk2Metis Conf overrides (tools_def.txt etc.) into edk2/Conf
if [ -f "$WORKSPACE/Conf/build_rule.txt" ]; then
    cp -f "$WORKSPACE/Conf/build_rule.txt"  "$EDK2_PATH/Conf/build_rule.txt"
    cp -f "$WORKSPACE/Conf/tools_def.txt"   "$EDK2_PATH/Conf/tools_def.txt"
fi

# Default fuzzing options
export AFL_USE_ASAN=1
export ASAN_OPTIONS=abort_on_error=1:detect_leaks=0:symbolize=0:allocator_may_return_null=1:detect_odr_violation=0

echo "Edk2Metis environment ready."
EOF
RUN chmod +x ${HOME}/init_edk2-metis_env.sh \
 && chown -R ${USERNAME}:${USERNAME} ${HOME}

WORKDIR /home/${USERNAME}/edk2-metis_workspace/Edk2Metis
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["bash", "-l"]

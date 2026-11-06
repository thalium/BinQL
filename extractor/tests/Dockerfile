FROM debian:bookworm@sha256:c4b9d852ddd2f2d751b3628ff2e5a4c03e4606cb422ba352f5a0d72b9c246a32

RUN dpkg --add-architecture i386
RUN dpkg --add-architecture armhf
RUN dpkg --add-architecture mips64
RUN dpkg --add-architecture ppc64el
RUN dpkg --add-architecture riscv64

RUN apt update && apt install -y \
    build-essential \
    gcc-12-multilib g++-12-multilib

RUN apt install -y \
    crossbuild-essential-armhf \
    crossbuild-essential-arm64 \
    crossbuild-essential-powerpc \
    crossbuild-essential-mips

RUN apt install -y \
    libc6:i386 libc6-dev:i386 libgcc-s1:i386 libstdc++6:i386

RUN apt install -y \
    libc6:armhf libc6-dev:armhf libgcc-s1:armhf libstdc++6:armhf

RUN apt install -y \
    gcc-arm-linux-gnueabi

RUN apt install -y \
    gcc-powerpc-linux-gnu \
    gcc-powerpc64-linux-gnu

RUN apt install -y \
    gcc-mips-linux-gnu \
    gcc-mips64-linux-gnuabi64

RUN apt install -y \
    gcc-riscv64-linux-gnu

# MSVC-ABI cross toolchain (clang targeting x86_64-pc-windows-msvc), used to
# build the stmt_try_throw fixture: Hex-Rays only reconstructs cit_try/cit_throw
# ctree nodes from MSVC's own C++ EH metadata, never from GCC/Itanium-ABI
# __cxa_throw call sequences (confirmed empirically, see TODO.md).
RUN apt update && apt install -y \
    clang-19 lld-19 curl ca-certificates xz-utils

# clang -fuse-ld=lld looks for an unversioned `lld-link`/`ld.lld` in PATH.
RUN ln -s /usr/bin/lld-link-19 /usr/local/bin/lld-link \
    && ln -s /usr/bin/ld.lld-19 /usr/local/bin/ld.lld

RUN curl -sL "https://github.com/Jake-Shadle/xwin/releases/download/0.9.0/xwin-0.9.0-x86_64-unknown-linux-musl.tar.gz" \
    | tar xz -C /usr/local/bin --strip-components=1 xwin-0.9.0-x86_64-unknown-linux-musl/xwin

RUN xwin --accept-license --cache-dir /tmp/xwin-cache splat --output /opt/msvc \
    && rm -rf /tmp/xwin-cache

WORKDIR /work

CMD ["make", "compile"]

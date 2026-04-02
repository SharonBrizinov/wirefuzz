FROM ubuntu:24.04

ARG WIRESHARK_VERSION=master
ARG NPROC=0

ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies for Wireshark + clang/LLVM for libfuzzer
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build flex bison \
    python3 \
    libglib2.0-dev libgcrypt20-dev libpcap-dev \
    libc-ares-dev libpcre2-dev libxml2-dev \
    libnghttp2-dev \
    liblz4-dev libzstd-dev libsnappy-dev \
    libspeexdsp-dev libsbc-dev \
    libnl-3-dev libnl-route-3-dev libnl-genl-3-dev \
    libsystemd-dev \
    git ca-certificates pkg-config \
    llvm llvm-dev lld clang clang-tools libclang-rt-dev \
    && rm -rf /var/lib/apt/lists/*

# Clone Wireshark at specified version
# Keep .git so make-version.py can generate vcs_version.h
RUN git clone --no-checkout https://gitlab.com/wireshark/wireshark.git /opt/wireshark \
    && cd /opt/wireshark \
    && git checkout ${WIRESHARK_VERSION} \
    && git submodule update --init --depth=1

# Replace fuzzshark.c with our version that supports WIREFUZZ_ENCAP env var
COPY docker/fuzzshark.c /opt/wireshark/fuzz/fuzzshark.c

# Build Wireshark with libfuzzer + ASAN + UBSAN
# Only build fuzzshark target (not all of Wireshark)
#
# On aarch64, clang's UBSan emits __muloti4 (128-bit overflow multiply) into
# shared libs, but this symbol lives in compiler-rt builtins which aren't
# automatically linked into .so files. We run cmake first to generate the ninja
# files, then use a Python script to inject the builtins archive into the
# LINK_LIBRARIES for the affected targets before building.
COPY docker/patch_ninja.py /opt/wirefuzz/patch_ninja.py
RUN cd /opt/wireshark \
    && mkdir -p build && cd build \
    && cmake -G Ninja .. \
        -DCMAKE_C_COMPILER=clang \
        -DCMAKE_CXX_COMPILER=clang++ \
        -DENABLE_FUZZER=ON \
        -DENABLE_ASAN=ON \
        -DENABLE_UBSAN=ON \
        -DBUILD_fuzzshark=ON \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_wireshark=OFF \
        -DBUILD_stratoshark=OFF \
        -DENABLE_LUA=OFF \
        -DENABLE_PLUGINS=ON \
        -DBUILD_sshdump=OFF \
        -DBUILD_ciscodump=OFF \
        -DBUILD_androiddump=OFF \
        -DBUILD_udpdump=OFF \
        -DBUILD_randpktdump=OFF \
        -DBUILD_sdjournal=OFF \
        -DBUILD_dpauxmon=OFF \
        -DBUILD_rawshark=OFF \
        -DBUILD_sharkd=OFF \
        -DBUILD_tfshark=OFF \
        -DBUILD_mmdbresolve=OFF \
        -DBUILD_dcerpcidl2wrs=OFF \
    && python3 /opt/wirefuzz/patch_ninja.py . \
    && ninja -j${NPROC:-4} fuzzshark

# Also build editcap and tshark for corpus preparation
RUN cd /opt/wireshark/build \
    && ninja -j${NPROC:-4} editcap tshark

# Put built tools on PATH
ENV PATH="/opt/wireshark/build/run:${PATH}"

# ASAN/UBSAN runtime options
ENV ASAN_OPTIONS="detect_leaks=0:allocator_may_return_null=1:print_stacktrace=1:detect_odr_violation=0"
ENV UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0"

# Copy entrypoint and tools
COPY docker/entrypoint.sh /opt/wirefuzz/entrypoint.sh
RUN chmod +x /opt/wirefuzz/entrypoint.sh

# Create directories for runtime
RUN mkdir -p /corpus /crashes /logs /dict

ENTRYPOINT ["/opt/wirefuzz/entrypoint.sh"]

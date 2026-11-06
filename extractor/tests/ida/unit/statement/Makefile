CC_x86_32   = gcc -m32
CC_x86_64   = gcc
CC_arm32    = arm-linux-gnueabi-gcc
CC_arm64    = aarch64-linux-gnu-gcc
CC_ppc32    = powerpc-linux-gnu-gcc
CC_ppc64    = powerpc64-linux-gnu-gcc
CC_mips32   = mips-linux-gnu-gcc
CC_mips64   = mips64-linux-gnuabi64-gcc
CC_riscv64  = riscv64-linux-gnu-gcc

CFLAGS      = -Wall -Wextra -O0 -g

# MSVC-ABI cross toolchain (clang + Microsoft's own CRT/SDK headers via xwin,
# baked into the Docker image). Only cit_try/cit_throw ctree reconstruction
# needs this -- Hex-Rays never recognizes GCC/Itanium-ABI __cxa_throw as a
# structured try/throw, only MSVC's C++ EH tables. x86_64 only: this is a
# single fixture binary, not a full arch matrix.
MSVC_ROOT   = /opt/msvc
# -Wl,/ignore:4099: MS's prebuilt CRT .lib objects reference PDBs they don't
# ship (D:\a\_work\...libcmt.amd64.pdb) -- silence the LNK4099 spam under -g.
CXX_MSVC    = clang++-19 -target x86_64-pc-windows-msvc -fms-compatibility -fms-extensions -fuse-ld=lld -O0 -g \
              -isystem $(MSVC_ROOT)/crt/include \
              -isystem $(MSVC_ROOT)/sdk/include/ucrt \
              -isystem $(MSVC_ROOT)/sdk/include/um \
              -isystem $(MSVC_ROOT)/sdk/include/shared \
              -L$(MSVC_ROOT)/crt/lib/x86_64 \
              -L$(MSVC_ROOT)/sdk/lib/ucrt/x86_64 \
              -L$(MSVC_ROOT)/sdk/lib/um/x86_64 \
              -Wl,/ignore:4099

SRC_DIR     = src
BIN_DIR     = bin

ARCHS       := x86_32 x86_64 arm32 arm64 ppc32 ppc64 mips32 mips64 riscv64

SRC_FILES   := $(wildcard $(SRC_DIR)/*.c)
TARGETS     := $(patsubst $(SRC_DIR)/%.c,%,$(SRC_FILES))
BINARIES    := $(foreach arch,$(ARCHS),$(foreach tgt,$(TARGETS),$(BIN_DIR)/$(tgt)_$(arch).bin))

MSVC_BINARIES := $(BIN_DIR)/stmt_try_throw_x86_64.bin

all: $(BINARIES) $(MSVC_BINARIES)

$(BIN_DIR)/stmt_try_throw_x86_64.bin: $(SRC_DIR)/stmt_try_throw.cpp | $(BIN_DIR)
	$(CXX_MSVC) $< -o $@

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/%_x86_32.bin: $(SRC_DIR)/%.c | $(BIN_DIR)
	$(CC_x86_32) $(CFLAGS) $< -o $@

$(BIN_DIR)/%_x86_64.bin: $(SRC_DIR)/%.c | $(BIN_DIR)
	$(CC_x86_64) $(CFLAGS) $< -o $@

$(BIN_DIR)/%_arm32.bin: $(SRC_DIR)/%.c | $(BIN_DIR)
	$(CC_arm32) $(CFLAGS) $< -o $@

$(BIN_DIR)/%_arm64.bin: $(SRC_DIR)/%.c | $(BIN_DIR)
	$(CC_arm64) $(CFLAGS) $< -o $@

$(BIN_DIR)/%_ppc32.bin: $(SRC_DIR)/%.c | $(BIN_DIR)
	$(CC_ppc32) $(CFLAGS) $< -o $@

$(BIN_DIR)/%_ppc64.bin: $(SRC_DIR)/%.c | $(BIN_DIR)
	$(CC_ppc64) $(CFLAGS) $< -o $@

$(BIN_DIR)/%_mips32.bin: $(SRC_DIR)/%.c | $(BIN_DIR)
	$(CC_mips32) $(CFLAGS) $< -o $@

$(BIN_DIR)/%_mips64.bin: $(SRC_DIR)/%.c | $(BIN_DIR)
	$(CC_mips64) $(CFLAGS) $< -o $@

$(BIN_DIR)/%_riscv64.bin: $(SRC_DIR)/%.c | $(BIN_DIR)
	$(CC_riscv64) $(CFLAGS) $< -o $@

clean:
	rm -rf $(BIN_DIR)
	rm -rf databases
	rm -rf $(SRC_DIR)/*.ql
	rm -rf $(SRC_DIR)/*.bqrs
	rm -rf $(SRC_DIR)/*.csv

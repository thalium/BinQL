CC_x86_32   = gcc -m32
CC_x86_64   = gcc
CC_arm32    = arm-linux-gnueabi-gcc
CC_arm64    = aarch64-linux-gnu-gcc
CC_ppc32    = powerpc-linux-gnu-gcc
CC_ppc64    = powerpc64-linux-gnu-gcc
CC_mips32   = mips-linux-gnu-gcc
CC_mips64   = mips64-linux-gnuabi64-gcc
CC_riscv64  = riscv64-linux-gnu-gcc

CFLAGS      = -Wall -Wextra -O0

SRC_DIR     = src
BIN_DIR     = bin

ARCHS       := x86_32 x86_64 arm32 arm64 ppc32 ppc64 mips32 mips64 riscv64

SRC_FILES   := $(wildcard $(SRC_DIR)/*.c)
TARGETS     := $(patsubst $(SRC_DIR)/%.c,%,$(SRC_FILES))
BINARIES    := $(foreach arch,$(ARCHS),$(foreach tgt,$(TARGETS),$(BIN_DIR)/$(tgt)_$(arch).bin))

all: $(BINARIES)

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

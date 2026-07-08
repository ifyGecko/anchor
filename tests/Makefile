# Builds baremetal firmware blobs for testing anchor.py.
#
# Add or remove entries in CASES to change which firmware images are built.
# Each case has the form  <arch>_<endian>_<base_hex>  where <arch>_<endian>
# has a matching pattern rule below and <base_hex> is the load address
# (no leading 0x).
#
# Output: build/<case>.bin  (raw firmware) plus the intermediate .elf.

BUILD    := build
SRC_DIR  := src
COMMON_C := $(SRC_DIR)/firmware.c
ARM_VEC_C:= $(SRC_DIR)/vectors_arm.c
LDSCRIPT := $(SRC_DIR)/link.ld

CASES := \
    arm_le_08000000 \
    arm_le_10000000 \
    arm_le_20000000 \
    mips32_be_bfc00000 \
    mips32_le_80010000 \
    ppc32_be_00100000

ALL_BINS := $(addprefix $(BUILD)/,$(addsuffix .bin,$(CASES)))

# -- shared compiler / linker flags --------------------------------------
CFLAGS_COMMON := -Os -nostdlib -nostartfiles -ffreestanding \
                 -fno-pic -fno-pie -fno-stack-protector \
                 -fno-asynchronous-unwind-tables -fno-unwind-tables \
                 -static
LDFLAGS_COMMON:= -Wl,--build-id=none -Wl,-no-pie -Wl,--no-warn-rwx-segments

# -- per-arch toolchains -------------------------------------------------
ARM_GCC       := arm-none-eabi-gcc
ARM_OBJCOPY   := arm-none-eabi-objcopy
ARM_FLAGS     := -mcpu=cortex-m3 -mthumb
ARM_LE_FLAGS  := $(ARM_FLAGS)
ARM_BE_FLAGS  := $(ARM_FLAGS) -mbig-endian
ARM_SRC       := $(COMMON_C) $(ARM_VEC_C)

MIPS_BE_GCC   := mips-linux-gnu-gcc
MIPS_BE_OBJC  := mips-linux-gnu-objcopy
MIPS_BE_FLAGS := -EB -mabi=32 -mno-abicalls -mno-shared

MIPS_LE_GCC   := mipsel-linux-gnu-gcc
MIPS_LE_OBJC  := mipsel-linux-gnu-objcopy
MIPS_LE_FLAGS := -EL -mabi=32 -mno-abicalls -mno-shared

PPC_BE_GCC    := powerpc-linux-gnu-gcc
PPC_BE_OBJC   := powerpc-linux-gnu-objcopy
PPC_BE_FLAGS  := -m32
# PPC uses libgcc helpers (_restgpr_*, _savegpr_*) that -nostdlib strips.
PPC_BE_LIBGCC := $(shell $(PPC_BE_GCC) -print-libgcc-file-name 2>/dev/null)

.PHONY: all clean list
.DEFAULT_GOAL := all

all: $(ALL_BINS)

list:
	@echo "test cases:"
	@printf "  %s\n" $(CASES)

clean:
	rm -rf $(BUILD)

$(BUILD):
	@mkdir -p $@

# -- pattern rules -------------------------------------------------------
# Each rule extracts the base address from the filename stem via $*
# and passes it to the linker as BASE_ADDR.

$(BUILD)/arm_le_%.bin: $(ARM_SRC) $(LDSCRIPT) | $(BUILD)
	$(ARM_GCC) $(ARM_LE_FLAGS) $(CFLAGS_COMMON) $(LDFLAGS_COMMON) \
	    -T $(LDSCRIPT) -Wl,--defsym=BASE_ADDR=0x$* \
	    $(ARM_SRC) -o $(BUILD)/arm_le_$*.elf
	$(ARM_OBJCOPY) -O binary $(BUILD)/arm_le_$*.elf $@

$(BUILD)/arm_be_%.bin: $(ARM_SRC) $(LDSCRIPT) | $(BUILD)
	$(ARM_GCC) $(ARM_BE_FLAGS) $(CFLAGS_COMMON) $(LDFLAGS_COMMON) \
	    -T $(LDSCRIPT) -Wl,--defsym=BASE_ADDR=0x$* \
	    $(ARM_SRC) -o $(BUILD)/arm_be_$*.elf
	$(ARM_OBJCOPY) -O binary $(BUILD)/arm_be_$*.elf $@

$(BUILD)/mips32_be_%.bin: $(COMMON_C) $(LDSCRIPT) | $(BUILD)
	$(MIPS_BE_GCC) $(MIPS_BE_FLAGS) $(CFLAGS_COMMON) $(LDFLAGS_COMMON) \
	    -T $(LDSCRIPT) -Wl,--defsym=BASE_ADDR=0x$* \
	    $(COMMON_C) -o $(BUILD)/mips32_be_$*.elf
	$(MIPS_BE_OBJC) -O binary $(BUILD)/mips32_be_$*.elf $@

$(BUILD)/mips32_le_%.bin: $(COMMON_C) $(LDSCRIPT) | $(BUILD)
	$(MIPS_LE_GCC) $(MIPS_LE_FLAGS) $(CFLAGS_COMMON) $(LDFLAGS_COMMON) \
	    -T $(LDSCRIPT) -Wl,--defsym=BASE_ADDR=0x$* \
	    $(COMMON_C) -o $(BUILD)/mips32_le_$*.elf
	$(MIPS_LE_OBJC) -O binary $(BUILD)/mips32_le_$*.elf $@

$(BUILD)/ppc32_be_%.bin: $(COMMON_C) $(LDSCRIPT) | $(BUILD)
	$(PPC_BE_GCC) $(PPC_BE_FLAGS) $(CFLAGS_COMMON) $(LDFLAGS_COMMON) \
	    -T $(LDSCRIPT) -Wl,--defsym=BASE_ADDR=0x$* \
	    $(COMMON_C) $(PPC_BE_LIBGCC) -o $(BUILD)/ppc32_be_$*.elf
	$(PPC_BE_OBJC) -O binary $(BUILD)/ppc32_be_$*.elf $@

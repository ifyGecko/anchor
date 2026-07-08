/* Linker script for test firmware images.
 *
 * BASE_ADDR is provided at link time via -Wl,--defsym=BASE_ADDR=0x...
 * so the same script works for every test case (arch/endian/base).
 *
 * .vectors is only produced by vectors_arm.c on ARM targets; on other
 * architectures the KEEP(*(.vectors)) line is a harmless no-op. */

ENTRY(_start)

SECTIONS
{
    . = BASE_ADDR;

    .text : {
        KEEP(*(.vectors))
        *(.text*)
        *(.rodata*)
        *(.data*)
        *(.sdata*)
        . = ALIGN(4);
    }

    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
        *(.debug*)
        *(.ARM.*)
        *(.MIPS.*)
        *(.reginfo)
        *(.mdebug*)
        *(.pdr)
        *(.gnu.attributes)
    }
}

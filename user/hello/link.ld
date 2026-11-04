ENTRY(_start)

SECTIONS
{
    . = 0x555510000000;

    .image : {
        *(.text._start)
        *(.text .text.*)
        *(.rodata .rodata.*)
        *(.data .data.*)
    }

    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    }

    /DISCARD/ : {
        *(.eh_frame*)
        *(.comment)
        *(.note*)
    }
}

/* Self-contained PIC image. 64K segment separation also supports 4K/16K hosts. */
ENTRY(plugin_entry)
PHDRS {
 text PT_LOAD FILEHDR PHDRS FLAGS(5);
 ro PT_LOAD FLAGS(4);
 data PT_LOAD FLAGS(6);
 dynamic PT_DYNAMIC FLAGS(4);
}
SECTIONS {
 . = SIZEOF_HEADERS;
 .text : { *(.text .text.*) } :text
 . = ALIGN(65536);
 .rodata : { *(.rodata .rodata.*) *(.data.rel.ro .data.rel.ro.*) } :ro
 .dynsym : { *(.dynsym) } :ro
 .dynstr : { *(.dynstr) } :ro
 .hash : { *(.hash) } :ro
 .gnu.hash : { *(.gnu.hash) } :ro
 .rela.dyn : { *(.rela .rela.*) } :ro
 .dynamic : { *(.dynamic) } :ro :dynamic
 . = ALIGN(65536);
 .data : { *(.data .data.*) *(.got .got.*) BYTE(0) } :data
 .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) } :data
 /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) *(.gnu.version*) }
}

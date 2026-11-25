# UDP capture plugin asset

The SDK embeds the trusted ARM64 ELF `udp_capture.cp` in `UdpCapLoad`.
Its source of truth is kernel/plugins/udp_capture.c; the matching source and
build inputs are included in udp_capture_source. There are no kernel-symbol
imports or per-packet plugin callbacks. The host owns the mmap ring.

Rebuild from this directory with the GNU AArch64 toolchain:

    python3 udp_capture_source/plugins/build.py udp_capture_source/plugins/udp_capture.c --out udp_capture.cp

The recorded binary was built with aarch64-linux-gnu-gcc 13.3.0. Input and output
SHA-256 values are in udp_capture.sha256.json. Different compiler versions can
produce a different ELF; deploy matching host, SDK and trusted plugin inputs.

LOAD carries image/configuration plus the target PID. CONTROL carries
[handle, CP_START, caller_mmap, mmap_bytes, 0]. CP_STOP drains and releases the
ring but retains the handle; UdpCapStop and session Stop/Drop use UNLOAD.
All reads consume shared memory without a transport call. A forked child cannot
read, stop, unmap or unload its parent's session through the owning wrapper.

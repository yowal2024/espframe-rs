# Shared native plugins

This SDK owns native plugin source, its freestanding build tooling and matching
host-interface headers in native/. A kernel source checkout is not required.

- native/plugins/tgcp.c and tgcp.h: reusable TGCP protocol and handshake.
- native/plugins/udp_capture.c: bounded UDP capture configuration.
- native/plugins/raw_rules.c: generic UDP byte rules.
- native/plugins/framed_crc.c: framed CRC example.
- native/plugins/read_replace.c: equal-length read replacement.
- native/plugins/build.py, runtime.c and plugin.lds: common ARM64 ELF toolchain.

UamEdge owns its RSA protocol source in rust/host/plugins/rsa/. Its plugin uses
this SDK's rsa_sdk.h. The kernel owns loading, resource lifetime, I/O and crypto
services; application protocol implementations do not live in the kernel repo.

From this directory, with aarch64-linux-gnu-gcc installed:

    python3 native/plugins/build.py native/plugins/udp_capture.c --out udp_capture.cp
    python3 native/plugins/build.py native/plugins/tgcp.c --out /tmp/tgcp.tp
    python3 native/plugins/build.py native/plugins/read_replace.c --out /tmp/read_replace.rp

UdpCapLoad embeds udp_capture.cp. Its authoritative source is native/plugins/
udp_capture.c; udp_capture.sha256.json records source/output hashes. It has no
per-packet callback; the host owns the mmap ring. UdpCapStart loads and binds;
UdpCapStop and session Stop/Drop unload the exact handle. Reads are memory-only.

Use the SDK Git revision pinned by each application's Cargo.toml/Cargo.lock.
Build application-owned plugins using this revision's native/plugins/build.py.
All shared interface headers must match the kernel; current kernel fixture
builders compare them after normalizing line endings before compiling. There is no ABI negotiation.

The recorded compiler is aarch64-linux-gnu-gcc 13.3.0. On 2026-11-25, plugins
rebuilt from project-owned sources matched the executed assets byte-for-byte.
GKI 5.10/6.1 QEMU exercised production-linked fixture modules, real traffic and
unload races. Full Android enforcing-policy app and physical-device coverage
remain unverified.

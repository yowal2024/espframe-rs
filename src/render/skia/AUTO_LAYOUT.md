# Cache member discovery

The user confirmed the shared-primitives APK works on their device. That
artifact is retained under `build/release-1.3.0-shared-skia/`.

This revision uses composeSurfaces for every supported sample, removing the
RequestCache::exists hook and its resolution branch. It replaces fixed Output+0x68 access with an offset
decoded from `Output::cacheClientCompositionRequests(uint32_t)`. It handles the
inspected direct pointer replacement and outlined unique_ptr reset forms.
It is deliberately a small AArch64 recognizer, not a general decompiler.

Validation requires:

- Symbol-aligned, nonzero function lengths; configuration is at most 512 bytes
  and composeSurfaces at most 64 KiB. No scanning outside symbol boundaries.
- A recognized prologue saving `this`, a zero-capacity branch, 56-byte cache
  allocation and a uint32 capacity store at cache+0.
- Matching offsets in cache assignment and clearing. For outlined reset, both
  paths must pass the same member address to the same helper, including the
  inspected shared epilogue variant.
- A matching pointer load in composeSurfaces from a preserved entry object
  register, followed by a null check. This is a structural cross-check, not a
  proof of arbitrary vendor control flow.
- An aligned offset in [8, 4096], and no conflicting candidates. Unknown forms
  produce an initialization error; there is no guessed-offset fallback.

Discovery runs once, before hook installation. It reads code only, never tries
candidate writes against a live Output. Discovery is required for every
composeSurfaces hook installation, including the supplied device binaries.
Only the member offset is discovered here. Cache capacity layout, allocation
size and synchronous ownership assumptions are explicitly constrained.

`tools/sf-skia/probe_cache.rs` includes the exact payload `layout.rs` decoder.
The static audit extracts bounded instructions from each ELF and invokes that
decoder for all six samples using the same composeSurfaces path as the payload.

| Sample | Decoded offset |
| --- | --- |
| Official Android 15 | 104 / 0x68 |
| Official Android 16 | 104 / 0x68 |
| Official Android 17 | 104 / 0x68 |
| Supplied Android 15 | 112 / 0x70 |
| Supplied Android 16 | 856 / 0x358 |
| Supplied Android 17 | 888 / 0x378 |

Report: `build/skia-auto-cache/static-audit.json`. This is static binary
analysis; no test suite or device test was run for this revision.

Subsequent revision: the user confirmed this auto-cache APK on the supplied
device samples. Android 15 dirty-output offsets are now also derived, and
ImageInfo creation is unified with bounded factory checks; see BOUNDS_INFO.md.
Paint, DisplaySettings and refcounts retain their documented constraints.
Successful cache discovery alone does not establish compatibility with an unknown ROM.

## PAC x20 compiler family (2026-10-20)

The liuqin Android 15 sample adds a 62-instruction PAC-enabled family with
`x20=this` and `w19=capacity`. Its decoder checks the full body, deriving the
member immediate from all four assignment/clear accesses. Internal branch
distances remain exact; relocated release calls must still agree on shared
targets. An independent composeSurfaces load/null check confirms the member.
This sample decodes to 840 / 0x348, without hardcoding that offset or checking
the model name. Unknown bodies continue to reject initialization.

The same sample has a 44-instruction extended ImageInfo factory using unsized
delete. Its complete argument/store/control-flow pattern is recognized and
classified as extended, preserving the required ROM destructor.

Regression fixtures and malformed-input tests live in `layout/`. The ordinary
host Skia unit suite includes these recognizers. To audit one extracted device
with `symbols/modules.json`, use:

```powershell
python tools/sf-skia/audit_adapters.py --samples build/sf-device-20261020-liuqin --single-version 15 --output build/sf-device-20261020-liuqin/fixed/static-audit.json
```

The existing six modern and four legacy samples, plus the new device sample,
pass the static audit. See `docs/reviews/2026-10-20-surfaceflinger-liuqin.md`
at the repository root for device evidence and validation limits.

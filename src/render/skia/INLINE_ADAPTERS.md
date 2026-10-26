# Inline API adapters, Android 15–17

See the [field layout audit](FIELD_LAYOUT_AUDIT.md) for the exact offsets and
differences checked against the six extracted binaries.
The subsequent [cache discovery revision](AUTO_LAYOUT.md) derives the cache
member offset from instructions instead of fixing it at Output+0x68.

This revision keeps the previously device-tested composition scope and all
host / imgui-rs interfaces. Runtime selection still starts with API 35/36/37,
then uses shared primitives where all inspected samples agree and selects
alternatives only for the remaining differences. No Build ID or device-name list is
used. Android 12–14 remain disabled.

The three official ARM64 emulator binaries and three supplied device binaries
pass static symbol resolution for this revision. This is not a runtime test.
Run `python tools/sf-skia/audit_adapters.py` from the repository root to reproduce
the read-only audit against `build/emulator-sf-analysis`. The report is
`build/skia-inline-adapters/static-audit.json` by default. The shared-primitives
release saves its report to `build/skia-shared-primitives/static-audit.json`.

| Missing API | Fallback and ownership |
| --- | --- |
| `SkSurface::getCanvas` | `SkSurface_Base::getCachedCanvas`. AOSP getCanvas directly delegates to this function, which also creates a canvas if needed. No surface field offset is used. |
| Canvas save (always shared) | `only_axis_aligned_saveBehind` with an empty rectangle. Its nonintersecting branch performs ordinary deferred save, with no pixel copy, clear, or layer allocation. Inspected official 15/16/17 addresses: 0x4685bc / 0x506d90 / 0x5940d4; supplied device addresses: 0x38b7fc / 0x59fbc4 / 0x753bd0. The old `save` resolution branch is removed. |
| Canvas restore (always shared) | Public `restore`. Each espframe scope adds exactly one save and balances its children. The `restoreToCount` branch and saved-count storage are removed. `internalSave` / `internalRestore` are not called directly. |
| SkData creation (always shared) | `PrivateNewWithCopy` exists in all six samples, accepts source/size in x0/x1 and returns an owned sk_sp through x8. It copies texture bytes into ROM-owned memory. No `MakeWithCopy` resolution branch remains. |
| `sk_sp<SkData>` destructor | `SkNVRefCnt<SkData>::unref` on a non-null remaining pointer, then clear the slot. This uses SkData's nonvirtual refcount, not the image/shader vtable release. |
| ImageInfo creation (always shared) | Always use `MakeN32Premul`; check the compact or extended ARM64 factory form for RGBA_8888 and premul. Convert source texture pixels to premultiplied alpha when creating the cached texture. Old Make overload branches are removed. See BOUNDS_INFO.md. |
| ImageInfo destructor | Use the ROM destructor when present. Only a checked complete compact null-colorspace factory permits no-op destruction. Extended factories require the ROM destructor. |
| Paint default constructor / setShader | Only when absent, require the complete compact-layout move-constructor instructions to match. Six owned pointers precede RGBA at +48, alpha at +60, width at +64, miter at +68 and flags at +72. Construct the documented default values and transfer one shader reference at +8. The ROM destructor releases it. Do not use `reset` on unconstructed storage. |
| Request cache (always shared) | Always hook `Output::composeSurfaces`; the `exists` symbol and branch are removed. Decode the member offset from assignment/reset instructions and cross-check the consumer; capacity at cache+0 remains a required instruction constraint. Recreate an empty cache with the same capacity, temporarily detach it during the synchronous compose call, then restore it on return. |

The cache wrapper preserves x0–x3, x8, LR and the return registers; the ROM owns
the `optional<unique_fd>` return storage and shared_ptr argument. The inspected
compose bodies only read the cache unique_ptr. Output ownership serializes the
operation on its composition thread. No output pointer is retained after the
call. Emptying before detachment prevents a stale cached overlay after shutdown.
This shared path allocates a small empty cache per active composition when the
output has caching enabled and has not been benchmarked.

The narrow instruction checks validate inline layout evidence, not identity.
They run before hooks are installed, respect symbol size, and reject unknown
instruction forms rather than applying guessed offsets. The cache recognizer
decodes offsets and relative branches; no fixed call address is used. Compiler variants may
therefore still require adaptation even at the same Android API level.

Evidence lives under each sample's `abi-evidence/`, including constructors,
destructors, saveBehind, getCachedCanvas, Info factories, cache configuration,
and `composeSurfaces.asm`. AOSP source snapshots are under
`build/emulator-sf-analysis/aosp-source/`.

Android 15's dirty-output fallback now derives offsets from checked inline
instructions and uses display bounds (see BOUNDS_INFO.md). DisplaySettings geometry uses
the previously inspected offsets; without tryCapture, final submission relies
on the inspected drawLayers control flow. These are not universal vendor ABI
guarantees. The preceding revision passed the user's device test; this revision
has compilation and static checks only, with no tests or device installation.

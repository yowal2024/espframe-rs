# Android 15 / 16 / 17 Skia compatibility

The evidence below concerns the three supplied device binaries. The broader
[Android 12–17 emulator symbol audit](EMULATOR_SYMBOL_AUDIT.md) initially found
missing symbols in official API 35/36/37 images. The subsequent
[inline adapters](INLINE_ADAPTERS.md) resolve those gaps in all six samples;
this does not establish compatibility with every build of those versions.

Selection uses `ro.build.version.sdk`: API 35/36/37 selects Android 15/16/17.
Build IDs and device names are not checked. Symbols are resolved dynamically,
including XZ `.gnu_debugdata`, before any hook installation.

## Shared drawing path

The current common-hook revision replaces mandatory tryCapture/initCanvas hooks
with drawLayersInternal and optional drawLayersFadeInternal scopes. tryCapture
is optional destination validation; scope exit clears metadata on every return.
The original sample evidence below describes the inspected binary call chains.
Inline API fallback selection and its static validation are documented separately.

All three samples provide tryCapture, initCanvas, GL/Ganesh Vulkan flushAndSubmit,
SkSurface::getCanvas, Output::beginFrame and composition cache exists.
Android 17 additionally provides Graphite Vulkan flushAndSubmit.
The current drawLayers scope records the engine and geometry. Optional capture
records final surface identity. Submission consumes the scope once and gets a
live canvas from the submitted surface. No recording canvas survives endCapture.
Scope exit clears aborted work. With capture present, intermediate surfaces
cannot consume the final output. The ARM64 wrapper preserves x0/x1/x2, x8 and LR,
then tail-calls the original; ROM code retains fence and sk_sp ownership.
No endCapture hook, tracing hook or fixed drawing-end instruction address is used.

## Android 15

Sample: Desktop/extracted_surfaceflinger/andorid15.
Skia is linked into /system/bin/surfaceflinger.

Disassembly evidence (ELF virtual addresses, before ASLR):

| Area | Evidence / adapter |
| --- | --- |
| Canvas scope | tryCapture 0x37b2e8, initCanvas 0x369258; GL submit 0x37686c, Vulkan submit 0x366d0c. |
| DisplaySettings | `initCanvas` reads physical rect +0x18, clip +0x28, rotation +0x88; unchanged. |
| Output name | `setName` 0x2e0770 formats `%s (%s)` with decimal display ID. `Display::isVirtual` 0x2da2a8 tests bit 63. Match physical IDs instead of the original panel's fixed ID. |
| Dirty region | `beginFrame` 0x2e4698 loads virtual base offset from vptr-0x258 and calls editState via base vptr+0xb0. `getDirtyRegion` 0x2e209c reads state dirty region +0xb0, viewport +0x18. Use ROM libui `Region::set(Rect const&)`. |
| Matrix | Missing resetMatrix: call ROM `SkCanvas::setMatrix(SkM44 const&)` 0x38e93c with identity matrix. |
| Paint storage | Constructor 0x3e4084 writes through +0x4b; shared 96-byte storage is sufficient. Destructor 0x3e437c releases the ROM-owned pointer fields. |
| ImageInfo | No-color-space Make 0x3c7818 returns through x8, zeroes color-space pointer +0 and writes through +0x17. For this overload only, no destructor work is needed. RasterFromData takes const Info&. |
| Data | Missing MakeWithCopy: `PrivateNewWithCopy` 0x3a9440 accepts source/size in x0/x1 and returns sk_sp through x8, including copy and zero-length handling. Existing ROM sk_sp<SkData> destructor 0x36996c remains available. |
| Vertices | Builder 0x44fbb0 allocates via system C++ operator new, initializes refcount +0; final release at 0x44fc44 calls system operator delete. Use matching system libc++ delete. |
| Shader/image ownership | setShader 0x3e4aac consumes and clears sk_sp slot; makeShader 0x5a4b04 uses refcount +8 and disposal vtable slot +0x10, as existing adapter expects. |
| Repaint Binder | onTransact jump table at 0x7fda8 maps 1008 to 0x27ccb4 (read bool, set HWC disable), 1010 to 0x27cb70 (five int32 values, HWC state last). |

## Android 16

Sample: Desktop/extracted_surfaceflinger/android16. This library matches the
previously supported binary. GL submission: 0x54b9e0; Vulkan: 0x51bcec.
The fixed physical-panel name has been replaced with DisplayId classification.

## Android 17

Sample: Desktop/extracted_surfaceflinger/android17.
Implementation: /system_ext/lib64/libsurfaceflinger.so.

| Area | Disassembly evidence (ELF virtual addresses) |
| --- | --- |
| Setup | tryCapture 0x6db730, initCanvas 0x6866cc; geometry offsets 24/40/136. |
| Submission | GL 0x6a1f38, Ganesh Vulkan 0x67c380, Graphite Vulkan 0x67d69c. Main/fade submit calls: 0x6994f0 / 0x68c6a4. |
| Lifetime | endCapture is inlined and may destroy the recording canvas. Fetch the final surface canvas at submission. |
| Paint | Constructor 0x7d0100 writes through +0x5f; reserve 96 bytes before the canary. |
| ImageInfo | Make 0x7a6dcc writes 32 bytes including owned pointer +0x18; use ROM destructor 0x6236dc. |
| Sampling | Factory 0xb3ea60 reads cubic +4, B/C +8/+12. Image/shader refcount +8, dispose vtable +16. |
| Outputs | setName 0x5cf074 formats decimal ID. HAL/GPU virtual generators set bit 63 at 0x551178 / 0x541428. |
| Repaint | Binder table 0x1bf096: 1008 -> 0x52ee58, 1010 -> 0x52efd8; HWC state remains the fifth int32. |
| Display query | API 37 enabled in bounded Parcel decoder. AOSP main DisplayInfo/DeviceProductInfo/DisplayCutout prefix matches API 35/36. Vendor runtime verification pending. |

## Validation

13 host Skia tests and 7 display Parcel tests passed (including API 37, matching
submission, duplicates, aborted frames, nesting, overflow and truncation).
Android ARM64 Release build and exact manager-block verification passed.
No device was connected; injection, rotation, sustained rendering, input and
shutdown remain untested. Version selection does not establish compatibility
with every vendor's private C++ ABI.

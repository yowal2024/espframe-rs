# Android 12 / 12L / 13 / 14

API 31–34 are selected by SDK level, alongside the existing API 35–37 path.
No Build ID or device-name selection is used. Host interfaces and the existing
imgui-rs snapshot/texture API are unchanged; all adapters live in espframe.

## Composition and submission

| Android | Main scope | Final submission | Geometry |
| --- | --- | --- | --- |
| 12 / 12L | SkiaGLRenderEngine::drawLayers, status return and output fd | SkSurface_Gpu::onFlush | physical 0, clip 16, orientation 208 |
| 13 | SkiaGLRenderEngine::drawLayersInternal, RenderEngineResult promise | SkSurface_Gpu::onFlush | physical 0, clip 16, orientation 112 |
| 14 | SkiaRenderEngine::drawLayersInternal, expected fence promise | SkSurface_Gpu::onFlush | physical 24, clip 40, orientation 136 |

The final virtual flush call is recognized inside the bounded draw function:
destination-equality check, zeroed flush info, access/state arguments, surface
vtable dispatch. The hook checks the original caller address against this
derived site and consumes the active draw scope once. Intermediate blur or
texture flushes do not use this site. No instruction addresses are hardcoded;
tryCapture/endCapture are neither required nor hooked for API 31–34.

The ROM retains surface ownership throughout the synchronous hook; the live
canvas is borrowed only while drawing. Drawing happens before the ROM's flush
and fence creation. The wrappers preserve x8 return storage, all actual input
arguments, original return values, and fd/promise ownership.

12/13 use the draw argument `useFramebufferCache`, which Output populates from
`layerStackInternal` / `layerFilter.toInternalDisplay`, as the internal-display
filter. 14 uses the existing output-name ID filter. Neither fixes screen size:
geometry comes from each composition's DisplaySettings, checked against the
actual canvas dimensions. Projection uses one setMatrix with exact right-angle
coefficients, removing the missing rotate dependency on Android 14.

## Inline adapters

- All versions suspend the request cache around composeSurfaces; its pointer
  offset is extracted from configuration code and cross-checked with compose.
  API 33's additional fifth register argument is preserved.
- 12/12L force getDirtyRegion's existing repaintEverything argument while active;
  its nontrivial Region result remains entirely ROM-owned. 13/14 use the ROM's
  dirtyEntireOutput before beginFrame.
- 12/12L obtain the already-created cached canvas after validating its surface
  destructor layout. A null cached canvas skips drawing. Their missing restore
  is reproduced from checked save/destructor code, including deferred count,
  stack depth, willRestore, internalRestore and didRestore.
- Compact ImageInfo fields are checked against byte-size and bitmap consumers.
  12/12L use the ROM colored Paint constructor; shader ownership is checked in
  move assignment. 13 uses the checked move constructor; 14 checks copy fields.
- Raster image/shader factories use the ROM. Static SkImageShader::Make receives
  an owned sk_sp slot; a remaining reference is released by the caller (12/12L),
  while moved-out slots need no release (13/14).
- 12/12L/13 sampling has no maxAniso field (confirmed in the ROM shader consumer
  and the corresponding Skia headers). The 12/12L nonempty copied SkData allocation
  is checked for null release callback and refcount at zero before using the
  matching libc++ delete. 13/14 retain ROM data-release functions.

## Verification and limits

`tools/sf-skia/audit_legacy.py` compiles the actual resource adapters against a
read-only ELF symbol provider and invokes the same cache/flush recognizers used
by the payload. It never calls Android functions. `audit_adapters.py` covers the
six existing Android 15–17 samples. All ten samples pass static resolution and
selected instruction/layout checks. Release compilation and APK signing checks
are separate; no device, emulator execution, or test suite was run.

The backend must actually be Skia: Android 12/12L can select GLESRenderEngine,
which these hooks do not convert to Skia. Synchronous SkiaGL on SF/main is
allowed on API 31/32; if a RenderEngine worker exists it is parked as well.
API 33+ still requires the existing dedicated-worker rendezvous.

This is bounded adaptation, not universal vendor compatibility. An unrecognized
final-flush body, required symbol, cache family, or inline object layout rejects
initialization before hook installation. DisplaySettings offsets are API-specific
and are not automatically inferred from a vendor-modified struct. Physical
external displays on 12/13 are excluded by the internal-display filter.

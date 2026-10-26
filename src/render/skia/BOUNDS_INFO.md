# Display bounds and shared ImageInfo revision

The user confirmed the preceding `release-1.3.0-auto-cache` APK on the supplied
device samples. This revision preserves its cache wrapper, Paint adapters,
DisplaySettings geometry and host/imgui-rs interfaces.

## Android 15 dirty-output adapter

The former adapter wrote the viewport rectangle at state+0x18 to dirtyRegion.
Inspection of two inlined dirtyEntireOutput bodies in the supplied Android 15
ELF showed the ROM instead constructs `{0, 0, displayWidth, displayHeight}` from
display bounds. The new adapter reproduces that operation.

When the standalone dirtyEntireOutput entry is absent, initialization reads
bounded setLayerFilter, setDisplaySize, beginFrame and getDirtyRegion code:

- Match the complete inspected setLayerFilter instruction structure, extracting
  virtual-base displacement, editState slot, dirtyRegion and display-bounds
  offsets. Both accessor sequences must agree. BL displacements are relocated.
- Cross-check beginFrame's entry accessor, getDirtyRegion's member access and
  the second inline Rect construction in setDisplaySize.
- Reject unknown instruction forms and out-of-range or inconsistent offsets
  before installing hooks. No candidate writes to live objects are attempted.

The supplied Android 15 result is virtual-base displacement 0x258, editState
slot 0xb0, dirtyRegion 0xb0 and bounds 0x64. These values are decoded, not chosen
by device identity. The other five samples retain their standalone ROM function.
The recognizer covers the inspected compiler form; it is not a general decoder
of arbitrary vendor implementations or a claim that every Android 15 matches.

## ImageInfo

All six samples now use MakeN32Premul(int,int). The old four-/five-argument Make
selection and InfoFactory enum are removed. A bounded instruction check requires
RGBA_8888=4, premul=2 and the inspected return-storage/initialization form.
Compact factories optionally start with BTI; extended factories match the
inspected complete bodies with BL destinations masked for relocation.

ROM ImageInfo destruction remains preferred. If missing, only the complete
compact null-colorspace factory permits no-op destruction. Extended factories
require a ROM destructor for their extra owned field.

Straight RGBA texture pixels are premultiplied once when creating a cached Skia
texture, using `(channel * alpha + 127) / 255`. Submitted vertices remain handled
by the existing path. Conversion is not repeated for each draw of that texture;
recreating a texture recreates the converted buffer. Small rounding differences
from the previous straight-alpha path are possible at translucent edges.

## Verification

`tools/sf-skia/probe_remaining.rs` includes the payload's actual recognizers.
`audit_adapters.py` runs them on file-backed instruction bytes alongside the
existing cache and Paint checks. All six Android 15/16/17 samples pass.
Report: `build/skia-bounds-info/static-audit.json`.

Release stays 1.3.0 / 130 with native and memory logs disabled. No test suite or
device test is run for this revision. Static analysis does not replace checking
rotation, refresh coverage and translucent textures on a device.

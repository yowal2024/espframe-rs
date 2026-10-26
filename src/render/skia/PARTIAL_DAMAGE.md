# Partial composition and moving-menu trails

The supplied Android 16 ELF has a damage path separate from
`Output::dirtyRegion`. `Output::composeSurfaces` builds damage from system
layers, calls `BufferDamage::computeDispDamage(int, int, Region&)`, updates
partial-composition metadata, and copies the result into DisplaySettings.
Its RenderEngine applies `androidFramework_setDeviceClipRestriction` before
clearing and drawing. Thus dirtyEntireOutput and disabling the request cache
alone do not guarantee that pixels under an old overlay position are redrawn.
The overlay is not a system Layer and is absent from this damage calculation.

When the BufferDamage symbol exists, an optional hook sets its input Region to
the full supplied width/height while the backend is active. It then calls the
original function, preserving its history and metadata updates. Expansion is
done before those updates, not just at the final overlay draw. Region mutation
uses libui's Region::set(Rect); no BufferDamage or DisplaySettings member offsets
are added. No device-name or Build ID selection is used.

The supplied Android 16 and 17 implementations copy the input damage into their
history and only expand it with older damage or full bounds. Both accept the
same four ARM64 arguments and return void. The seven official Android 12/12L/
13/14/15/16/17 samples and the supplied Android 15 have no such symbol; this
optional hook is skipped there. An inlined or different vendor damage pipeline
still needs separate evidence; this is not a universal compatibility claim.

This trades partial-composition savings for correct background redraw while
the backend is active. Validation is static ELF inspection and release
compilation only; the reported Android 16 trail needs device confirmation.

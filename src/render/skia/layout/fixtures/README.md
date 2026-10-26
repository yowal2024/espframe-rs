# Instruction regression fixtures

Read-only ELF extraction from Xiaomi liuqin / 23046RP50C, Android 15 API 35,
build `OS3.0.7.0.VMYCNXM`, on 2026-10-20. These raw AArch64 function bytes
are parsed as data; tests never execute Android code.

Source: `/system_ext/lib64/libsurfaceflinger.so`, SHA256
`405a2145d7401b7a8a6e2b3feae28a3f9edddb74568571eb44713184d54f2fd1`.

| Fixture | ELF virtual address | Bytes | Function |
| --- | --- | --- | --- |
| cache-pac-x20.bin | 0x43e4bc | 248 | Output::cacheClientCompositionRequests |
| compose-pac-x20.bin | 0x443c30 | 7444 | Output::composeSurfaces |
| n32-extended-unsized.bin | 0x59fb28 | 176 | SkImageInfo::MakeN32Premul(int,int) |

SHA256, in the same order:

```text
9f2d5a736dc9f6a8bbade9b238d45a939c5458043def05128469632423093a0b
257d40565be95f2e786aa8208bdaf95a30cbe56353c9378ea351da7542f5c077
0be36771a7920706df83a84e150110ee45e2c542a93e0971912a3c2e35d75bd9
```

Tests derive alternate offsets and relocation deltas from these original
instructions, and corrupt register roles, replacement paths, helper agreement,
consumer evidence, branches and object stores to check rejection.

## NP06J Android 16 adapters (2026-10-24)

The following function bytes come from the supplied
`surfaceflinger_np06j_16.bin`, Android API note 36, Build ID
`e02e597c266d3267e86d835bb648ddf1`, SHA256
`0a22f42054807628eced7a40fe2c6f83dc4951a3873a73676670d10c0e4b5e46`.
Build identity is recorded only for provenance, never used by the adapters.

| Fixture | ELF address | Bytes | Function |
| --- | --- | --- | --- |
| dirty-short-filter.bin | 0x33230c | 168 | Output::setLayerFilter |
| dirty-short-size.bin | 0x332168 | 284 | Output::setDisplaySize |
| dirty-short-begin.bin | 0x3384d0 | 268 | Output::beginFrame |
| dirty-short-region.bin | 0x333400 | 76 | Output::getDirtyRegion |
| canvas-extended-direction.bin | 0x3bab68 | 564 | SkiaRenderEngine::initCanvas |
| vertices-plain-make.bin | 0x4b3fe0 | 704 | SkVertices::MakeCopy |
| vertices-plain-builder.bin | 0x4b3b54 | 360 | SkVertices::Builder::init |

SHA256, in the same order:

```text
aa6e767e48d396cd9a73d3cad1b66cc83bce1564b63b447eb3a7d6102b85836b
7ae3a9b71b4983c22ebe8052fe11b34ce34c2f1f4302561f7428eed68e3650fa
d8843f47e2123f2fc592529f49fa9ddd9dd7bd8dac0d8aa25948b9c6145f41e2
35d1a7697ac0e340cb036ad2ea44a5cc0ff624897caaf41a3eb8a3a6da8c1386
d044437dcfb7c1bb1971d907f9ebef73edd32d0eaf45a8db5166c01a55450d4d
1e86532a96287de8e50b232a398970e446a3e35d9be9080e58c9e1011b045a42
ee84dc60916ecbe2c86d2d48a7891caf51df37e31fca84c0235c72d1c7849b25
```

`canvas-common.bin` is the 3,504-byte initCanvas at `0x24ee3c` from the
existing official Android 16 sample (`build/emulator-sf-analysis/android16`).
Source ELF SHA256:
`4338eab8c3bb13723e5f09bbc1bb7f8e2949c24411aa25854fcabad721bd9402`;
fixture SHA256:
`c23020aaf06cc167a882ead7dc84a49e782d1771f626a245c24f1df5040e9b68`.
It exercises the outlined angle-table form and the existing orientation
offset, alongside the new inline-table sample. These fixtures are read as
data only; no extracted instructions are executed by tests.

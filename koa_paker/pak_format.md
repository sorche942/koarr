# Kingdoms of Amalur Re‑Reckoning `.pak` Format (KARl v1)

This document summarizes what we have confirmed so far via reverse‑engineering
the game binary and validating against real packs.

## Header (0x18 bytes)

All observed packs use the `KARl` magic (little‑endian). The code also checks
for `KARb`, which likely indicates big‑endian.

```
0x00  char[4]  magic        "KARl" or "KARb"
0x04  u32      version      observed: 1
0x08  u32      block_size   observed: 16
0x0C  u32      field44      observed: 4096
0x10  u64      toc_offset   absolute file offset
```

## TOC (at `toc_offset`)

```
u32 countA
u32 countB
countA entries:
  u32 a   // CRC32(filename)
  u32 b   // offset_units
  u32 c   // uncompressed_size | flag
```

Observed semantics (confirmed against `initial_0.pak`):
- `a` == CRC32 of the filename (UTF‑8), matches `assetinfos.bin`.
- `b` == data offset in units of `block_size` (16).
  `data_offset = b * block_size`.
- `c` low 31 bits == uncompressed size.
- `c` high bit is a flag (rare; still unclear).

### countB table (partial)

If `countB > 0`, the file contains a second table and a small string blob.
Observed layout for `initial_0.pak` (`countB == 4`):

```
countB entries:
  u16
  u16
  u32
  u64
string_table:
  N null‑terminated strings (N == countB observed)
```

The exact semantics are still unknown; it behaves like a small name/metadata
table distinct from the main asset list.

## Entry Data (at `data_offset`)

Each entry begins with a small per‑file header:

```
u32 uncompressed_size
u32 chunk_count
u32 chunk_sizes[chunk_count]
u8  chunk_data[sum(chunk_sizes)]
```

Notes:
- `chunk_count` is typically `ceil(uncompressed_size / 0x1000)`.
- `chunk_data` is a concatenation of `chunk_count` compressed chunks.
- The last chunk can be shorter than 0x1000 after decompression.
- `chunk_count == 0` is valid and means raw data follows directly:
  `u8 raw_data[uncompressed_size]` (no custom chunk decompression).

## Compression (`fcn.140012800`)

Each chunk is compressed using a custom bitstream LZ variant:

- The output starts with one raw byte: `dst[0] = src[0]`.
- The rest is decoded from an MSB‑first bitstream starting at `src[1]`.
- There are literals, short matches, long matches, and a single‑byte copy mode.
- End‑of‑chunk is signaled by a short‑match token with `offset == 0`.

### Bitstream details (confirmed)

Let `read_bit()` read MSB‑first bits, and `read_byte()` read the next byte.

```
literal:
  if bit == 0:
    output read_byte()

long match:
  if bit == 1 and next_bit == 0:
    code = read_prefix_code()
    if last_was_match == false and code == 2:
      length = read_prefix_code()
      copy from last_offset, length bytes
    else:
      if last_was_match:
        offset = ((code - 2) << 8) | read_byte()
      else:
        offset = ((code - 3) << 8) | read_byte()
      last_offset = offset
      length = read_prefix_code()
      length += 1 if offset > 31999
      length += 1 if offset > 0x4FF
      length += 2 if offset < 0x80
      copy from offset, length bytes

single‑byte mode / short match:
  if bit == 1 and next_bit == 1:
    if next_bit == 1:
      value = read 4 bits
      output 0x00 if value == 0 else output dst[-value]
    else:
      b = read_byte()
      length = (b & 1) + 2
      offset = b >> 1
      if offset == 0: end‑of‑chunk
      copy from offset, length bytes
      last_offset = offset
```

`read_prefix_code()` is:
```
value = 1
do:
  value = value * 2 + read_bit()
  cont = read_bit()
while cont == 1
return value
```

## Name Mapping (`assetinfos.bin`)

Filenames are *not* stored in the `.pak` TOC. The game uses `assetinfos.bin`
files to map names to CRC32:

```
u32 countA
u32 countB
repeat (countA + countB) times:
  u32 asset_id
  u8  type
  u8  name_len
  char[name_len] name
```

This layout matches what the existing `assetinfos_tool.py` parser expects.

## Known Tools

- `koa_pak_extractor.py`: TOC parsing + decompression + extraction.
- `assetinfos_tool.py`: name table parsing and CSV export.
- `koa_pak_builder.py`: simple KARl/v1 mod pack builder (raw entries).

## Open Questions

- Full meaning of `countB` entries.
- Meaning of the high‑bit flag in `c`.
- Confirmed behavior for `KARb` (big‑endian).

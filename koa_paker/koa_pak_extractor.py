#!/usr/bin/env python3
"""
Probe Kingdoms of Amalur Re-Reckoning .pak TOC entries.

This script follows the read order observed in the game's unpacker:
  - magic (KARl/KARb)
  - version (u32)
  - block_size (u32)
  - field44 (u32)
  - toc_offset (u64)
  - TOC at toc_offset:
      u32 countA
      u32 countB
      countA entries of (u32 a, u32 b, u32 c)

Observed entry semantics for initial_0.pak (KARl, version=1):
  - a == CRC32(filename) for most filenames in assetinfos.bin
  - b == data offset in units of block_size (header block_size is 16)
  - c low 31 bits == uncompressed size, high bit appears to be a flag

At offset = b * block_size, the file data begins with:
  u32 uncompressed_size
  u32 chunk_count
  u32 chunk_sizes[chunk_count]
  followed by concatenated compressed chunks (algorithm unknown)

Compression details are based on fcn.140012800 (custom bitstream LZ variant).
See unpacked/pak_format.md for full format notes.
"""

from __future__ import annotations

import argparse
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional


@dataclass
class PakHeader:
    magic: bytes
    version: int
    block_size: int
    field44: int
    toc_offset: int


@dataclass
class TocEntry:
    index: int
    a: int
    b: int
    c: int

    @property
    def c_flag(self) -> bool:
        return (self.c & 0x80000000) != 0

    @property
    def c_value(self) -> int:
        return self.c & 0x7FFFFFFF


@dataclass
class EntryBlob:
    offset: int
    uncompressed_size: int
    chunk_count: int
    chunk_sizes: List[int]
    data_offset: int
    compressed_size: int
    end_offset: int


def read_header(pak_path: Path) -> PakHeader:
    with pak_path.open("rb") as f:
        data = f.read(24)
    if len(data) < 24:
        raise ValueError(f"{pak_path} too small to be a .pak")
    magic = data[:4]
    version, block_size, field44 = struct.unpack_from("<III", data, 4)
    toc_offset = struct.unpack_from("<Q", data, 16)[0]
    return PakHeader(magic, version, block_size, field44, toc_offset)


def iter_toc_entries(pak_path: Path, header: PakHeader) -> Iterable[TocEntry]:
    with pak_path.open("rb") as f:
        f.seek(header.toc_offset)
        countA, countB = struct.unpack("<II", f.read(8))
        data = f.read(countA * 12)
    for idx, (a, b, c) in enumerate(struct.iter_unpack("<III", data)):
        yield TocEntry(idx, a, b, c)


def read_entry_blob(pak_path: Path, header: PakHeader, entry: TocEntry) -> EntryBlob:
    offset = entry.b * header.block_size
    with pak_path.open("rb") as f:
        f.seek(offset)
        header_bytes = f.read(8)
        if len(header_bytes) < 8:
            raise ValueError(f"entry @0x{offset:X} too small for header")
        uncompressed_size, chunk_count = struct.unpack("<II", header_bytes)
        sizes = list(struct.unpack("<" + "I" * chunk_count, f.read(chunk_count * 4)))
        data_offset = f.tell()
    # chunk_count == 0 is a valid "raw" storage mode in stock packs:
    # data follows directly after the 8-byte per-entry header.
    compressed_size = sum(sizes) if chunk_count > 0 else uncompressed_size
    end_offset = data_offset + compressed_size
    return EntryBlob(
        offset=offset,
        uncompressed_size=uncompressed_size,
        chunk_count=chunk_count,
        chunk_sizes=sizes,
        data_offset=data_offset,
        compressed_size=compressed_size,
        end_offset=end_offset,
    )


def load_assetinfos(assetinfos_path: Path) -> List[str]:
    data = assetinfos_path.read_bytes()
    if len(data) < 8:
        raise ValueError(f"{assetinfos_path} too small")
    count_a, count_b = struct.unpack_from("<II", data, 0)
    total = count_a + count_b
    names: List[str] = []
    pos = 8
    for _ in range(total):
        if pos + 6 > len(data):
            break
        _asset_id = struct.unpack_from("<I", data, pos)[0]
        name_len = data[pos + 5]
        pos += 6
        name = data[pos : pos + name_len].decode("ascii", errors="ignore")
        pos += name_len
        names.append(name)
    return names


def crc32_name(name: str) -> int:
    return zlib.crc32(name.encode("utf-8")) & 0xFFFFFFFF


class BitReader:
    def __init__(self, data: bytes, start: int = 0) -> None:
        self._data = data
        self._pos = start
        self._buf = 0
        self._left = 0

    def read_bit(self) -> int:
        if self._left == 0:
            if self._pos >= len(self._data):
                raise EOFError("bitstream exhausted")
            self._buf = self._data[self._pos]
            self._pos += 1
            self._left = 8
        bit = (self._buf >> 7) & 1
        self._buf = (self._buf << 1) & 0xFF
        self._left -= 1
        return bit

    def read_byte(self) -> int:
        if self._pos >= len(self._data):
            raise EOFError("byte stream exhausted")
        b = self._data[self._pos]
        self._pos += 1
        return b


def _read_code(br: BitReader) -> int:
    value = 1
    while True:
        value = (value << 1) | br.read_bit()
        cont = br.read_bit()
        if cont == 0:
            return value


def _copy_from_out(out: bytearray, offset: int, length: int) -> None:
    if offset <= 0 or offset > len(out):
        raise ValueError(f"invalid backref offset {offset} (out_len={len(out)})")
    for _ in range(length):
        out.append(out[-offset])


def decompress_chunk(data: bytes, expected_len: Optional[int] = None) -> bytes:
    if not data:
        return b""
    out = bytearray()
    out.append(data[0])
    br = BitReader(data, start=1)
    last_offset = 0
    last_was_match = False
    while True:
        if br.read_bit() == 0:
            out.append(br.read_byte())
            last_was_match = False
        else:
            if br.read_bit() == 0:
                code = _read_code(br)
                if not last_was_match:
                    if code == 2:
                        length = _read_code(br)
                        if length:
                            if last_offset == 0:
                                raise ValueError("repeat-offset with last_offset=0")
                            _copy_from_out(out, last_offset, length)
                        last_was_match = True
                        if expected_len is not None and len(out) > expected_len:
                            raise ValueError("decompressed past expected length")
                        continue
                    offset = ((code - 3) << 8) | br.read_byte()
                else:
                    offset = ((code - 2) << 8) | br.read_byte()
                last_offset = offset
                length = _read_code(br)
                if offset > 31999:
                    length += 1
                if offset > 0x4FF:
                    length += 1
                if offset < 0x80:
                    length += 2
                if length:
                    _copy_from_out(out, offset, length)
                last_was_match = True
            else:
                if br.read_bit() == 1:
                    value = 0
                    for _ in range(4):
                        value = (value << 1) | br.read_bit()
                    if value == 0:
                        out.append(0)
                    else:
                        out.append(out[-value])
                    last_was_match = False
                else:
                    b = br.read_byte()
                    length = (b & 1) + 2
                    offset = b >> 1
                    if offset == 0:
                        break
                    last_offset = offset
                    _copy_from_out(out, offset, length)
                    last_was_match = True
        if expected_len is not None and len(out) > expected_len:
            raise ValueError("decompressed past expected length")
    return bytes(out)


def decompress_entry(pak_path: Path, header: PakHeader, entry: TocEntry) -> bytes:
    return _decompress_entry(pak_path, header, entry, verbose=False)


def _decompress_entry(
    pak_path: Path, header: PakHeader, entry: TocEntry, verbose: bool = False
) -> bytes:
    blob = read_entry_blob(pak_path, header, entry)
    if blob.chunk_count == 0:
        with pak_path.open("rb") as f:
            f.seek(blob.data_offset)
            data = f.read(blob.uncompressed_size)
        if len(data) != blob.uncompressed_size:
            raise ValueError(
                f"raw entry short read ({len(data)} != {blob.uncompressed_size})"
            )
        return data

    remaining = blob.uncompressed_size
    out = bytearray()
    with pak_path.open("rb") as f:
        f.seek(blob.data_offset)
        for idx, comp_size in enumerate(blob.chunk_sizes):
            comp = f.read(comp_size)
            if len(comp) != comp_size:
                raise ValueError(f"chunk {idx} short read ({len(comp)} != {comp_size})")
            expected = min(0x1000, remaining) if remaining > 0 else None
            if verbose:
                exp_note = expected if expected is not None else "?"
                print(f"    chunk {idx}: comp={comp_size} expect={exp_note}")
            dec = decompress_chunk(comp, expected_len=expected)
            if expected is not None and len(dec) != expected:
                raise ValueError(f"chunk {idx} size {len(dec)} != expected {expected}")
            out.extend(dec)
            if verbose:
                print(f"    chunk {idx}: out={len(dec)} total_out={len(out)}")
            if remaining:
                remaining -= expected or 0
    if len(out) != blob.uncompressed_size:
        raise ValueError(f"decompressed size {len(out)} != header {blob.uncompressed_size}")
    return bytes(out)


def _safe_output_path(base_dir: Path, name: str) -> Path:
    safe = name.replace("\\", "/")
    parts = [p for p in safe.split("/") if p not in ("", ".", "..")]
    if not parts:
        parts = [name.replace("/", "_").replace("\\", "_")]
    return base_dir.joinpath(*parts)


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe KOAR .pak TOC entries.")
    parser.add_argument("--pak", required=True, type=Path, help="Path to .pak file")
    parser.add_argument("--name", help="Filename to hash (CRC32) and lookup")
    parser.add_argument("--hash", dest="hash_value", help="Hex or decimal hash to lookup")
    parser.add_argument("--assetinfos", type=Path, help="assetinfos.bin for name candidates")
    parser.add_argument("--limit", type=int, default=20, help="Limit matches printed")
    parser.add_argument(
        "--inspect",
        action="store_true",
        help="Print per-entry blob header info (chunk count/sizes).",
    )
    parser.add_argument(
        "--dump-raw",
        type=Path,
        help="Dump raw compressed blob(s) to this directory (header+sizes+data).",
    )
    parser.add_argument(
        "--dump-all",
        action="store_true",
        help="Dump all entries (requires --assetinfos for filenames).",
    )
    parser.add_argument(
        "--extract",
        type=Path,
        help="Decompress and write matched entries to this directory.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print more detailed logs (chunk sizes, offsets, etc.).",
    )

    args = parser.parse_args()

    header = read_header(args.pak)
    file_size = args.pak.stat().st_size
    print(f"magic={header.magic} version={header.version} block_size={header.block_size} field44={header.field44}")
    print(f"toc_offset=0x{header.toc_offset:X}")
    if args.verbose:
        print(f"pak_size={file_size} bytes")

    lookup_hash: Optional[int] = None
    if args.name:
        lookup_hash = crc32_name(args.name)
        print(f"name='{args.name}' crc32=0x{lookup_hash:08X} ({lookup_hash})")
    elif args.hash_value:
        hv = args.hash_value.strip().lower()
        lookup_hash = int(hv, 16) if hv.startswith("0x") else int(hv)
        print(f"hash=0x{lookup_hash:08X} ({lookup_hash})")

    crc_name_map: dict[int, str] = {}
    # Optional: list candidate names for the hash and build a crc->name map
    if args.assetinfos:
        names = load_assetinfos(args.assetinfos)
        for n in names:
            crc = crc32_name(n)
            if crc not in crc_name_map:
                crc_name_map[crc] = n
        if lookup_hash is not None:
            matches = [n for n in names if crc32_name(n) == lookup_hash]
            print(f"assetinfos candidates: {len(matches)}")
            for n in matches[: args.limit]:
                print(f"  {n}")

    # Scan TOC
    countA = 0
    countB = 0
    with args.pak.open("rb") as f:
        f.seek(header.toc_offset)
        countA, countB = struct.unpack("<II", f.read(8))
    print(f"countA={countA} countB={countB}")
    if args.verbose:
        toc_bytes = 8 + countA * 12
        print(f"toc_bytes(min)={toc_bytes} (excludes countB table + string table)")

    if lookup_hash is None and not args.dump_all:
        return 0

    matches: List[TocEntry] = []
    if args.dump_all:
        matches = list(iter_toc_entries(args.pak, header))
    else:
        for entry in iter_toc_entries(args.pak, header):
            if entry.a == lookup_hash:
                matches.append(entry)
                if len(matches) >= args.limit:
                    break

    if not matches:
        print("no TOC entries matched hash")
        return 0

    print("matches:")
    for e in matches:
        offset = e.b * header.block_size
        print(
            f"  idx={e.index} a=0x{e.a:08X} b=0x{e.b:08X} c=0x{e.c:08X} "
            f"flag={int(e.c_flag)} offset=0x{offset:X}"
        )

        if args.inspect:
            blob = read_entry_blob(args.pak, header, e)
            size_note = ""
            if blob.uncompressed_size != e.c_value:
                size_note = f" (entry c={e.c_value})"
            preview = ", ".join(str(s) for s in blob.chunk_sizes[:8])
            if blob.chunk_count > 8:
                preview += ", ..."
            print(
                f"    blob: uncompressed={blob.uncompressed_size}{size_note} "
                f"chunks={blob.chunk_count} comp_total={blob.compressed_size} "
                f"data=0x{blob.data_offset:X}..0x{blob.end_offset:X}"
            )
            print(f"    chunk_sizes: [{preview}]")
            if args.verbose:
                running = blob.data_offset
                for idx, sz in enumerate(blob.chunk_sizes[:8]):
                    print(f"    chunk[{idx}] off=0x{running:X} size={sz}")
                    running += sz

        if args.dump_raw:
            out_dir = args.dump_raw
            out_dir.mkdir(parents=True, exist_ok=True)
            # Choose a stable filename
            base = f"hash_{e.a:08X}_idx_{e.index}"
            name_hint = None
            if args.name and not args.dump_all:
                name_hint = args.name
            elif crc_name_map:
                name_hint = crc_name_map.get(e.a)
            if name_hint:
                base = name_hint.replace("/", "_").replace("\\", "_")
            out_path = out_dir / f"{base}.pakblob"
            blob = read_entry_blob(args.pak, header, e)
            with args.pak.open("rb") as f:
                f.seek(blob.offset)
                raw = f.read(blob.end_offset - blob.offset)
            out_path.write_bytes(raw)
            print(f"    dumped raw blob -> {out_path}")

        if args.extract:
            out_dir = args.extract
            out_dir.mkdir(parents=True, exist_ok=True)
            name_hint = None
            if args.name and not args.dump_all:
                name_hint = args.name
            elif crc_name_map:
                name_hint = crc_name_map.get(e.a)
            if name_hint:
                out_path = _safe_output_path(out_dir, name_hint)
            else:
                out_path = out_dir / f"hash_{e.a:08X}_idx_{e.index}.bin"
            out_path.parent.mkdir(parents=True, exist_ok=True)
            if args.verbose:
                print(f"    extracting {out_path} ...")
            data = _decompress_entry(args.pak, header, e, verbose=args.verbose)
            out_path.write_bytes(data)
            print(f"    extracted -> {out_path} ({len(data)} bytes)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

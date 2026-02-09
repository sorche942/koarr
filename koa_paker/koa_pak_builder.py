#!/usr/bin/env python3
"""
Build Kingdoms of Amalur Re-Reckoning .pak files for mod loading.

This builder writes KARl/v1 packs with a countB=0 TOC and stores each asset in
"raw" mode (chunk_count == 0), which is used by stock packs for many entries.
"""

from __future__ import annotations

import argparse
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List

DEFAULT_MAGIC = b"KARl"
DEFAULT_VERSION = 1
DEFAULT_BLOCK_SIZE = 16
DEFAULT_FIELD44 = 4096
COPY_CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True)
class SourceEntry:
    virtual_path: str
    source_path: Path
    size: int
    hash_name: str
    hash_value: int


@dataclass(frozen=True)
class TocEntry:
    hash_value: int
    offset_units: int
    size: int
    virtual_path: str
    source_path: Path


def crc32_name(name: str) -> int:
    return zlib.crc32(name.encode("utf-8")) & 0xFFFFFFFF


def normalize_virtual_path(path: str) -> str:
    path = path.strip().replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    while path.startswith("/"):
        path = path[1:]

    parts: List[str] = []
    for part in path.split("/"):
        if part == "" or part == ".":
            continue
        if part == "..":
            raise ValueError(f"invalid virtual path '{path}': '..' is not allowed")
        parts.append(part)

    if not parts:
        raise ValueError(f"invalid virtual path '{path}'")
    return "/".join(parts)


def parse_manifest_line(raw: str, line_no: int) -> tuple[str, str]:
    line = raw.split("#", 1)[0].strip()
    if not line:
        raise ValueError("empty")

    if ";" in line:
        left, right = line.split(";", 1)
    elif "=" in line:
        left, right = line.split("=", 1)
    else:
        raise ValueError(
            f"line {line_no}: expected 'virtual_path;source_path' or 'virtual_path=source_path'"
        )

    virtual = left.strip()
    source = right.strip()
    if not virtual or not source:
        raise ValueError(f"line {line_no}: both virtual and source path are required")
    return virtual, source


def collect_from_dir(input_dir: Path) -> List[tuple[str, Path]]:
    pairs: List[tuple[str, Path]] = []
    for path in sorted(input_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(input_dir)
        pairs.append((rel.as_posix(), path))
    return pairs


def collect_from_manifest(manifest: Path) -> List[tuple[str, Path]]:
    pairs: List[tuple[str, Path]] = []
    for line_no, raw in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        try:
            virtual, source_text = parse_manifest_line(raw, line_no)
        except ValueError as exc:
            if str(exc) == "empty":
                continue
            raise

        src = Path(source_text)
        if not src.is_absolute():
            src = (manifest.parent / src).resolve()
        pairs.append((virtual, src))
    return pairs


def build_source_entries(
    pairs: Iterable[tuple[str, Path]],
    *,
    hash_mode: str,
    dedupe_virtual_paths: bool,
) -> List[SourceEntry]:
    by_virtual: dict[str, SourceEntry] = {}
    ordered: List[SourceEntry] = []

    for virtual_raw, source_path in pairs:
        virtual_path = normalize_virtual_path(virtual_raw)
        if not source_path.exists() or not source_path.is_file():
            raise FileNotFoundError(f"source file not found: {source_path}")

        hash_name = virtual_path.lower() if hash_mode == "lower" else virtual_path
        size = source_path.stat().st_size
        if size > 0xFFFFFFFF:
            raise ValueError(f"{source_path} is too large ({size} bytes)")

        entry = SourceEntry(
            virtual_path=virtual_path,
            source_path=source_path,
            size=size,
            hash_name=hash_name,
            hash_value=crc32_name(hash_name),
        )

        if virtual_path in by_virtual:
            if dedupe_virtual_paths:
                idx = next(i for i, e in enumerate(ordered) if e.virtual_path == virtual_path)
                ordered[idx] = entry
                by_virtual[virtual_path] = entry
                continue
            raise ValueError(
                f"duplicate virtual path '{virtual_path}' from {by_virtual[virtual_path].source_path} "
                f"and {source_path}"
            )

        by_virtual[virtual_path] = entry
        ordered.append(entry)

    return ordered


def write_aligned_padding(f, block_size: int) -> None:
    pos = f.tell()
    pad = (-pos) % block_size
    if pad:
        f.write(b"\x00" * pad)


def write_raw_file_data(f, src: Path, size: int) -> None:
    with src.open("rb") as fin:
        remaining = size
        while remaining:
            chunk = fin.read(min(COPY_CHUNK_SIZE, remaining))
            if not chunk:
                raise IOError(f"short read while copying {src}")
            f.write(chunk)
            remaining -= len(chunk)


def build_pak(
    entries: List[SourceEntry],
    output_path: Path,
    *,
    block_size: int,
    field44: int,
) -> List[TocEntry]:
    toc_entries: List[TocEntry] = []
    with output_path.open("wb") as f:
        # Placeholder header; TOC offset is patched after data is written.
        f.write(struct.pack("<4sIIIQ", DEFAULT_MAGIC, DEFAULT_VERSION, block_size, field44, 0))

        for e in entries:
            write_aligned_padding(f, block_size)
            offset = f.tell()
            if offset % block_size != 0:
                raise RuntimeError("entry offset alignment failure")

            # Per-entry header:
            #   u32 uncompressed_size
            #   u32 chunk_count (=0 => raw data follows)
            f.write(struct.pack("<II", e.size, 0))
            write_raw_file_data(f, e.source_path, e.size)

            toc_entries.append(
                TocEntry(
                    hash_value=e.hash_value,
                    offset_units=offset // block_size,
                    size=e.size,
                    virtual_path=e.virtual_path,
                    source_path=e.source_path,
                )
            )

        toc_offset = f.tell()
        sorted_toc = sorted(toc_entries, key=lambda t: (t.hash_value, t.virtual_path))
        f.write(struct.pack("<II", len(sorted_toc), 0))
        for e in sorted_toc:
            f.write(struct.pack("<III", e.hash_value, e.offset_units, e.size))

        f.seek(0)
        f.write(struct.pack("<4sIIIQ", DEFAULT_MAGIC, DEFAULT_VERSION, block_size, field44, toc_offset))

    return sorted_toc


def print_collisions(entries: List[SourceEntry]) -> None:
    by_hash: dict[int, List[SourceEntry]] = {}
    for e in entries:
        by_hash.setdefault(e.hash_value, []).append(e)

    collisions = {h: lst for h, lst in by_hash.items() if len(lst) > 1}
    if not collisions:
        return

    print(f"warning: {len(collisions)} CRC32 hash collision bucket(s) detected:")
    for h, lst in sorted(collisions.items()):
        names = ", ".join(e.virtual_path for e in lst)
        print(f"  0x{h:08X}: {names}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build KOAR KARl/v1 .pak files for mods.")
    parser.add_argument("--output", required=True, type=Path, help="Output .pak path")
    parser.add_argument(
        "--input-dir",
        type=Path,
        help="Source directory. Every file is added with a virtual path relative to this folder.",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        help="Mapping file: one entry per line as 'virtual_path;source_path' or 'virtual_path=source_path'.",
    )
    parser.add_argument(
        "--hash-mode",
        choices=["lower", "as-is"],
        default="lower",
        help="Path normalization for CRC32 hashing (default: lower).",
    )
    parser.add_argument(
        "--dedupe-virtual-paths",
        action="store_true",
        help="If the same virtual path appears multiple times, keep the last occurrence.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate inputs and show stats without writing the .pak.",
    )

    args = parser.parse_args()

    if bool(args.input_dir) == bool(args.manifest):
        parser.error("provide exactly one of --input-dir or --manifest")

    output_path = args.output.resolve()

    if args.input_dir:
        input_dir = args.input_dir.resolve()
        pairs = collect_from_dir(input_dir)
        pairs = [(v, s) for (v, s) in pairs if s.resolve() != output_path]
    else:
        pairs = collect_from_manifest(args.manifest.resolve())

    if not pairs:
        raise ValueError("no files to pack")

    entries = build_source_entries(
        pairs,
        hash_mode=args.hash_mode,
        dedupe_virtual_paths=args.dedupe_virtual_paths,
    )
    print_collisions(entries)

    total_size = sum(e.size for e in entries)
    print(f"entries: {len(entries)}")
    print(f"payload bytes: {total_size}")
    print(f"hash mode: {args.hash_mode}")

    if args.dry_run:
        print("dry-run complete (no output written).")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)

    toc_entries = build_pak(
        entries,
        output_path,
        block_size=DEFAULT_BLOCK_SIZE,
        field44=DEFAULT_FIELD44,
    )

    print(f"wrote: {output_path}")
    print(f"toc entries: {len(toc_entries)}")
    print("first TOC rows:")
    for row in toc_entries[:10]:
        print(
            f"  hash=0x{row.hash_value:08X} off_units={row.offset_units} "
            f"size={row.size} path={row.virtual_path}"
        )
    if len(toc_entries) > 10:
        print(f"  ... ({len(toc_entries) - 10} more)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

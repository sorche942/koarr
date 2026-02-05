#!/usr/bin/env python3
"""
Parse Kingdoms of Amalur Re-Reckoning assetinfos.bin files.

Format (best-effort, based on observed data):
  u32 count_a
  u32 count_b
  repeat (count_a + count_b) times:
    u32 asset_id
    u8  tag
    u8  name_len
    char name[name_len]  # ASCII, not null-terminated

This tool supports stats, dumps, and simple lookups.
"""

from __future__ import annotations

import argparse
import csv
import json
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, Iterator, Tuple


class AssetInfosParseError(RuntimeError):
    pass


def _read_bytes(path: Path) -> bytes:
    data = path.read_bytes()
    if len(data) < 8:
        raise AssetInfosParseError(f"{path} is too small to be a valid assetinfos file.")
    return data


def _parse_header(data: bytes) -> Tuple[int, int]:
    count_a, count_b = struct.unpack_from("<II", data, 0)
    return count_a, count_b


def iter_entries(data: bytes, count: int) -> Iterator[Tuple[int, int, str, int]]:
    """
    Yield (asset_id, tag, name, offset) for each entry.
    """
    pos = 8
    for _ in range(count):
        if pos + 6 > len(data):
            raise AssetInfosParseError("Unexpected EOF while reading entry header.")
        asset_id = struct.unpack_from("<I", data, pos)[0]
        tag = data[pos + 4]
        name_len = data[pos + 5]
        pos += 6
        if pos + name_len > len(data):
            raise AssetInfosParseError("Unexpected EOF while reading entry name.")
        name_bytes = data[pos : pos + name_len]
        try:
            name = name_bytes.decode("ascii")
        except UnicodeDecodeError:
            name = name_bytes.decode("latin-1")
        entry_offset = pos - 6
        pos += name_len
        yield asset_id, tag, name, entry_offset

    if pos != len(data):
        # There may be trailing bytes, but we at least note it.
        raise AssetInfosParseError(
            f"Parsed {count} entries, but file has {len(data) - pos} trailing bytes."
        )


def cmd_stats(path: Path) -> int:
    data = _read_bytes(path)
    count_a, count_b = _parse_header(data)
    total = count_a + count_b

    tag_counts: Counter[int] = Counter()
    ext_counts: Counter[str] = Counter()
    tag_ext_counts: Dict[int, Counter[str]] = defaultdict(Counter)

    for _, tag, name, _ in iter_entries(data, total):
        tag_counts[tag] += 1
        ext = "." + name.rsplit(".", 1)[1] if "." in name else "(no_ext)"
        ext_counts[ext] += 1
        tag_ext_counts[tag][ext] += 1

    print(f"File: {path}")
    print(f"Counts: header_a={count_a}, header_b={count_b}, total={total}")
    print("")
    print("Tag counts:")
    for tag, count in tag_counts.most_common():
        print(f"  0x{tag:02x}  {count}")
    print("")
    print("Top extensions overall:")
    for ext, count in ext_counts.most_common(15):
        print(f"  {ext}  {count}")
    print("")
    print("Top extensions by tag:")
    for tag, count in tag_counts.most_common():
        print(f"  Tag 0x{tag:02x}")
        for ext, ext_count in tag_ext_counts[tag].most_common(8):
            print(f"    {ext}  {ext_count}")

    return 0


def _write_csv(
    entries: Iterable[Tuple[int, int, str, int]],
    out_path: Path,
    delimiter: str,
    reverse: bool,
) -> None:
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter=delimiter)
        if reverse:
            writer.writerow(["name", "asset_id", "tag", "tag_hex"])
            for asset_id, tag, name, _ in entries:
                writer.writerow([name, asset_id, tag, f"0x{tag:02x}"])
        else:
            writer.writerow(["asset_id", "tag", "tag_hex", "name"])
            for asset_id, tag, name, _ in entries:
                writer.writerow([asset_id, tag, f"0x{tag:02x}", name])


def _write_jsonl(
    entries: Iterable[Tuple[int, int, str, int]],
    out_path: Path,
    reverse: bool,
) -> None:
    with out_path.open("w", encoding="utf-8") as f:
        for asset_id, tag, name, _ in entries:
            if reverse:
                obj = {"name": name, "asset_id": asset_id, "tag": tag, "tag_hex": f"0x{tag:02x}"}
            else:
                obj = {"asset_id": asset_id, "tag": tag, "tag_hex": f"0x{tag:02x}", "name": name}
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def cmd_dump(path: Path, out_path: Path, fmt: str, reverse: bool) -> int:
    data = _read_bytes(path)
    count_a, count_b = _parse_header(data)
    total = count_a + count_b

    entries = iter_entries(data, total)

    if fmt == "csv":
        _write_csv(entries, out_path, delimiter=",", reverse=reverse)
    elif fmt == "tsv":
        _write_csv(entries, out_path, delimiter="\t", reverse=reverse)
    elif fmt == "jsonl":
        _write_jsonl(entries, out_path, reverse=reverse)
    else:
        raise AssetInfosParseError(f"Unsupported format: {fmt}")

    print(f"Wrote {total} entries to {out_path}")
    return 0


def cmd_lookup(path: Path, asset_id: int | None, name: str | None) -> int:
    if asset_id is None and name is None:
        raise AssetInfosParseError("lookup requires --id or --name.")
    if asset_id is not None and name is not None:
        raise AssetInfosParseError("lookup accepts only one of --id or --name.")

    data = _read_bytes(path)
    count_a, count_b = _parse_header(data)
    total = count_a + count_b

    if asset_id is not None:
        for entry_id, tag, entry_name, _ in iter_entries(data, total):
            if entry_id == asset_id:
                print(f"{asset_id} -> {entry_name} (tag=0x{tag:02x})")
                return 0
        print(f"{asset_id} not found")
        return 1

    if name is not None:
        for entry_id, tag, entry_name, _ in iter_entries(data, total):
            if entry_name == name:
                print(f"{name} -> {entry_id} (tag=0x{tag:02x})")
                return 0
        print(f"{name} not found")
        return 1

    return 1


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Parse assetinfos.bin files.")
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Path to assetinfos.bin (e.g., initial_0/assetinfos.bin)",
    )

    subparsers = parser.add_subparsers(dest="cmd", required=True)

    subparsers.add_parser("stats", help="Show counts and top extensions.")

    dump = subparsers.add_parser("dump", help="Dump entries to a file.")
    dump.add_argument("--out", required=True, type=Path, help="Output file path.")
    dump.add_argument(
        "--format",
        required=True,
        choices=["csv", "tsv", "jsonl"],
        help="Output format.",
    )
    dump.add_argument(
        "--reverse",
        action="store_true",
        help="Output name->id mapping instead of id->name.",
    )

    lookup = subparsers.add_parser("lookup", help="Lookup by id or name.")
    lookup.add_argument("--id", type=int, help="Asset ID to lookup.")
    lookup.add_argument("--name", type=str, help="Asset name to lookup.")

    args = parser.parse_args(argv)

    try:
        if args.cmd == "stats":
            return cmd_stats(args.input)
        if args.cmd == "dump":
            return cmd_dump(args.input, args.out, args.format, args.reverse)
        if args.cmd == "lookup":
            return cmd_lookup(args.input, args.id, args.name)
    except AssetInfosParseError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

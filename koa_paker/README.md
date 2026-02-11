# KOA Pak Tools

This folder contains:

- `koa_pak_extractor.py`: inspect/extract `.pak` contents.
- `assetinfos_tool.py`: inspect `assetinfos.bin`.
- `koa_pak_builder.py`: build mod `.pak` files for use with `koa_pak_hook`.

## Extract Pak Files

```bash
python3 koa_pak_extractor.py \
  --pak /path/to/initial_0.pak \
  --dump-all \
  --extract /path/to/out
```

For stock game packs, the extractor now auto-loads names from the in-pack
`_filenames.bin`, so `--assetinfos` is optional for naming.
`--assetinfos` is still supported and can be merged with that map.

## Build A Mod Pak (Directory Mode)

Every file under `my_mod_files/` is added with its relative path as virtual path:

```bash
python3 koa_pak_builder.py \
  --input-dir /path/to/my_mod_files \
  --output /path/to/core_fix.pak
```

## Build A Mod Pak (Manifest Mode)

Manifest format: one line per entry.

`virtual_path;source_path`

Example:

```text
content/design/scripts/example.luac;./build/example.luac
250070.dds;./textures/250070.dds
```

Build:

```bash
python3 koa_pak_builder.py \
  --manifest /path/to/mod_manifest.txt \
  --output /path/to/core_fix.pak
```

## Hash Mode

The game TOC key is `CRC32(path)`. By default the builder hashes `virtual_path`
in lowercase (`--hash-mode lower`), which matches stock content naming style.
Use `--hash-mode as-is` if you need exact-case hashing.

## Hook Load Order Example

`mods/load_order.txt`:

```text
100;/gamebuild;/mods/core_fix.pak;-2
```

Then copy your built pak to the game folder so it resolves as
`/mods/core_fix.pak` for `koa_pak_hook`.

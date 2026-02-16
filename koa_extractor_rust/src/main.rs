use anyhow::{Context, Result, anyhow};
use byteorder::{LittleEndian, ReadBytesExt, ByteOrder};
use clap::Parser;
use crc32fast::Hasher;
use memmap2::Mmap;
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(author, version, about = "High-performance KOAR .pak extractor in Rust")]
struct Args {
    /// Path to the .pak file
    #[arg(short, long)]
    pak: PathBuf,

    /// Directory to extract files into
    #[arg(short, long)]
    output: PathBuf,

    /// Disable using _filenames.bin for naming
    #[arg(long, default_value_t = false)]
    no_filenames: bool,
}

struct PakHeader {
    block_size: u32,
    toc_offset: u64,
}

#[derive(Debug)]
struct TocEntry {
    hash: u32,
    offset_units: u32,
    size_flag: u32,
}

impl TocEntry {
    fn uncompressed_size(&self) -> u32 {
        self.size_flag & 0x7FFFFFFF
    }
}

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    buf: u8,
    bits_left: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8], start: usize) -> Self {
        Self {
            data,
            pos: start,
            buf: 0,
            bits_left: 0,
        }
    }

    #[inline(always)]
    fn read_bit(&mut self) -> Result<u8> {
        if self.bits_left == 0 {
            if self.pos >= self.data.len() {
                return Err(anyhow!("Bitstream exhausted at pos {}", self.pos));
            }
            self.buf = self.data[self.pos];
            self.pos += 1;
            self.bits_left = 8;
        }
        let bit = (self.buf >> 7) & 1;
        self.buf <<= 1;
        self.bits_left -= 1;
        Ok(bit)
    }

    #[inline(always)]
    fn read_byte(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() {
            return Err(anyhow!("Byte stream exhausted at pos {}", self.pos));
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }
}

#[inline(always)]
fn read_prefix_code(br: &mut BitReader) -> Result<u32> {
    let mut value = 1u32;
    loop {
        value = (value << 1) | (br.read_bit()? as u32);
        if br.read_bit()? == 0 {
            return Ok(value);
        }
    }
}

fn decompress_chunk(data: &[u8], expected_len: usize) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity(expected_len);
    out.push(data[0]);
    let mut br = BitReader::new(data, 1);
    let mut last_offset = 0usize;
    let mut last_was_match = false;

    while out.len() < expected_len {
        if br.read_bit()? == 0 {
            out.push(br.read_byte()?);
            last_was_match = false;
        } else {
            if br.read_bit()? == 0 {
                let code = read_prefix_code(&mut br)?;
                let offset: usize;
                let mut length: usize;

                if !last_was_match {
                    if code == 2 {
                        length = read_prefix_code(&mut br)? as usize;
                        if length > 0 {
                            if last_offset == 0 {
                                return Err(anyhow!("Repeat-offset with last_offset=0"));
                            }
                            copy_match(&mut out, last_offset, length);
                        }
                        last_was_match = true;
                        continue;
                    }
                    offset = (((code - 3) << 8) | (br.read_byte()? as u32)) as usize;
                } else {
                    offset = (((code - 2) << 8) | (br.read_byte()? as u32)) as usize;
                }

                last_offset = offset;
                length = read_prefix_code(&mut br)? as usize;
                
                if offset > 31999 { length += 1; }
                if offset > 0x4FF { length += 1; }
                if offset < 0x80 { length += 2; }
                
                if length > 0 {
                    copy_match(&mut out, offset, length);
                }
                last_was_match = true;
            } else {
                if br.read_bit()? == 1 {
                    let mut value = 0u8;
                    for _ in 0..4 {
                        value = (value << 1) | br.read_bit()?;
                    }
                    if value == 0 {
                        out.push(0);
                    } else {
                        let val = out[out.len() - value as usize];
                        out.push(val);
                    }
                    last_was_match = false;
                } else {
                    let b = br.read_byte()?;
                    let length = ((b & 1) + 2) as usize;
                    let offset = (b >> 1) as usize;
                    if offset == 0 {
                        break;
                    }
                    last_offset = offset;
                    copy_match(&mut out, offset, length);
                    last_was_match = true;
                }
            }
        }
    }
    Ok(out)
}

#[inline(always)]
fn copy_match(out: &mut Vec<u8>, offset: usize, length: usize) {
    for _ in 0..length {
        let val = out[out.len() - offset];
        out.push(val);
    }
}

fn decompress_entry(mmap: &Mmap, header: &PakHeader, entry: &TocEntry) -> Result<Vec<u8>> {
    let offset = entry.offset_units as u64 * header.block_size as u64;
    if offset >= mmap.len() as u64 {
        return Err(anyhow!("Entry offset 0x{:X} out of bounds", offset));
    }
    
    let mut cursor = Cursor::new(&mmap[offset as usize..]);
    
    let uncompressed_size = cursor.read_u32::<LittleEndian>()?;
    let chunk_count = cursor.read_u32::<LittleEndian>()? as usize;
    
    if chunk_count == 0 {
        let data_start = offset as usize + 8;
        let data_end = data_start + uncompressed_size as usize;
        if data_end > mmap.len() {
            return Err(anyhow!("Raw entry data out of bounds"));
        }
        return Ok(mmap[data_start..data_end].to_vec());
    }

    let mut chunk_sizes = Vec::with_capacity(chunk_count);
    for _ in 0..chunk_count {
        chunk_sizes.push(cursor.read_u32::<LittleEndian>()? as usize);
    }

    let mut out = Vec::with_capacity(uncompressed_size as usize);
    let mut data_pos = offset as usize + cursor.position() as usize;
    let mut remaining = uncompressed_size as usize;

    for &comp_size in &chunk_sizes {
        if data_pos + comp_size > mmap.len() {
            return Err(anyhow!("Chunk data out of bounds"));
        }
        let chunk_data = &mmap[data_pos..data_pos + comp_size];
        let expected = if remaining > 0x1000 { 0x1000 } else { remaining };
        let decompressed = decompress_chunk(chunk_data, expected)?;
        out.extend_from_slice(&decompressed);
        data_pos += comp_size;
        remaining -= decompressed.len();
    }

    Ok(out)
}

fn crc32(name: &str) -> u32 {
    let mut hasher = Hasher::new();
    hasher.update(name.as_bytes());
    hasher.finalize()
}

fn main() -> Result<()> {
    let args = Args::parse();
    let file = File::open(&args.pak).context("Failed to open .pak file")?;
    let mmap = unsafe { Mmap::map(&file).context("Failed to mmap .pak file")? };

    if mmap.len() < 24 || &mmap[0..4] != b"KARl" {
        return Err(anyhow!("Not a KARl .pak file or file too small"));
    }

    let block_size = LittleEndian::read_u32(&mmap[8..12]);
    let toc_offset = LittleEndian::read_u64(&mmap[16..24]);
    let header = PakHeader { block_size, toc_offset };

    if toc_offset >= mmap.len() as u64 {
        return Err(anyhow!("TOC offset 0x{:X} out of bounds", toc_offset));
    }

    let mut toc_cursor = Cursor::new(&mmap[toc_offset as usize..]);
    let count_a = toc_cursor.read_u32::<LittleEndian>()?;
    let _count_b = toc_cursor.read_u32::<LittleEndian>()?;

    let mut entries = Vec::with_capacity(count_a as usize);
    for _ in 0..count_a {
        entries.push(TocEntry {
            hash: toc_cursor.read_u32::<LittleEndian>()?,
            offset_units: toc_cursor.read_u32::<LittleEndian>()?,
            size_flag: toc_cursor.read_u32::<LittleEndian>()?,
        });
    }

    let mut name_map = HashMap::new();
    if !args.no_filenames {
        let filenames_hash = crc32("_filenames.bin");
        if let Some(entry) = entries.iter().find(|e| e.hash == filenames_hash) {
            println!("Found _filenames.bin, loading names...");
            if let Ok(data) = decompress_entry(&mmap, &header, entry) {
                let mut pos = 0;
                while pos + 8 <= data.len() {
                    // Check if we hit the trailer (countA, countB)
                    if pos + 8 == data.len() { break; }

                    let hash = LittleEndian::read_u32(&data[pos..pos+4]);
                    let len = LittleEndian::read_u32(&data[pos+4..pos+8]) as usize;
                    pos += 8;
                    if pos + len > data.len() { break; }
                    
                    let name_bytes = &data[pos..pos+len];
                    if let Ok(name) = std::str::from_utf8(name_bytes) {
                        name_map.insert(hash, name.to_string());
                    } else {
                        // Fallback to latin-1 if utf-8 fails
                        let name = name_bytes.iter().map(|&b| b as char).collect::<String>();
                        name_map.insert(hash, name);
                    }
                    pos += len;
                }
                println!("Loaded {} names from _filenames.bin", name_map.len());
            }
        }
    }

    fs::create_dir_all(&args.output)?;

    println!("Extracting {} entries...", entries.len());

    entries.par_iter().for_each(|entry| {
        let name = name_map.get(&entry.hash).cloned().unwrap_or_else(|| format!("{:08X}.bin", entry.hash));
        let out_path = args.output.join(name.replace("\\", "/"));
        
        if let Some(parent) = out_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        match decompress_entry(&mmap, &header, entry) {
            Ok(data) => {
                match File::create(&out_path) {
                    Ok(mut f) => {
                        if let Err(e) = f.write_all(&data) {
                            eprintln!("Failed to write to {:?}: {}", out_path, e);
                        }
                    }
                    Err(e) => eprintln!("Failed to create file {:?}: {}", out_path, e),
                }
            }
            Err(e) => eprintln!("Failed to decompress 0x{:08X}: {}", entry.hash, e),
        }
    });

    println!("Extraction complete.");
    Ok(())
}

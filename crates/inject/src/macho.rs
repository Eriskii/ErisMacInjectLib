//! Reads the payload dylib and lays it out as it should appear inside another process: segments
//! copied to their offsets, chained fixups applied. Only what our payloads need is supported
//! (thin or fat arm64, chained fixups with 64-bit pointers).

use std::ffi::CStr;

const CPU_TYPE_ARM64: u32 = 0x0100_000C;
const CPU_SUBTYPE_MASK: u32 = 0x00FF_FFFF;
const CPU_SUBTYPE_ARM64E: u32 = 2;
const MH_MAGIC_64: u32 = 0xFEED_FACF;
const FAT_MAGIC: u32 = 0xCAFE_BABE;
const FAT_MAGIC_64: u32 = 0xCAFE_BABF;

const LC_SEGMENT_64: u32 = 0x19;
const LC_SYMTAB: u32 = 0x2;
const LC_LOAD_DYLIB: u32 = 0xC;
const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
const LC_REEXPORT_DYLIB: u32 = 0x8000_001F;
const LC_LOAD_UPWARD_DYLIB: u32 = 0x8000_0023;
const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;

const DYLD_CHAINED_PTR_64: u16 = 2;
const DYLD_CHAINED_PTR_64_OFFSET: u16 = 6;
const DYLD_CHAINED_PTR_START_NONE: u16 = 0xFFFF;

pub struct Segment {
    pub name: String,
    pub vmaddr: u64,
    pub vmsize: u64,
    fileoff: u64,
    filesize: u64,
    pub initprot: i32,
}

pub struct Image<'a> {
    file: &'a [u8],
    pub segments: Vec<Segment>,
    chained_fixups: Option<(usize, usize)>,
    symtab: Option<(usize, usize, usize)>,
    pub dylibs: Vec<String>,
}

fn u16_at(b: &[u8], at: usize) -> Result<u16, String> {
    b.get(at..at + 2).map(|s| u16::from_le_bytes(s.try_into().unwrap())).ok_or_else(truncated)
}

fn u32_at(b: &[u8], at: usize) -> Result<u32, String> {
    b.get(at..at + 4).map(|s| u32::from_le_bytes(s.try_into().unwrap())).ok_or_else(truncated)
}

fn u64_at(b: &[u8], at: usize) -> Result<u64, String> {
    b.get(at..at + 8).map(|s| u64::from_le_bytes(s.try_into().unwrap())).ok_or_else(truncated)
}

fn be32_at(b: &[u8], at: usize) -> Result<u32, String> {
    b.get(at..at + 4).map(|s| u32::from_be_bytes(s.try_into().unwrap())).ok_or_else(truncated)
}

fn be64_at(b: &[u8], at: usize) -> Result<u64, String> {
    b.get(at..at + 8).map(|s| u64::from_be_bytes(s.try_into().unwrap())).ok_or_else(truncated)
}

fn cstr_at(b: &[u8], at: usize) -> Result<&str, String> {
    CStr::from_bytes_until_nul(b.get(at..).ok_or_else(truncated)?)
        .map_err(|_| truncated())?
        .to_str()
        .map_err(|_| "non-UTF-8 name".to_string())
}

fn truncated() -> String {
    "payload is truncated or malformed".to_string()
}

fn is_plain_arm64(cputype: u32, cpusubtype: u32) -> bool {
    cputype == CPU_TYPE_ARM64 && cpusubtype & CPU_SUBTYPE_MASK != CPU_SUBTYPE_ARM64E
}

/// The plain arm64 slice of a thin or fat Mach-O.
fn arm64_slice(file: &[u8]) -> Result<&[u8], String> {
    let magic = be32_at(file, 0)?;
    if magic != FAT_MAGIC && magic != FAT_MAGIC_64 {
        return Ok(file);
    }
    let wide = magic == FAT_MAGIC_64;
    let entry = if wide { 32 } else { 20 };
    for i in 0..be32_at(file, 4)? as usize {
        let at = 8 + i * entry;
        let (offset, size) = if wide {
            (be64_at(file, at + 8)? as usize, be64_at(file, at + 16)? as usize)
        } else {
            (be32_at(file, at + 8)? as usize, be32_at(file, at + 12)? as usize)
        };
        if is_plain_arm64(be32_at(file, at)?, be32_at(file, at + 4)?) {
            return file.get(offset..offset + size).ok_or_else(truncated);
        }
    }
    Err("payload has no arm64 slice".into())
}

impl<'a> Image<'a> {
    pub fn parse(file: &'a [u8]) -> Result<Self, String> {
        let file = arm64_slice(file)?;
        if u32_at(file, 0)? != MH_MAGIC_64 || !is_plain_arm64(u32_at(file, 4)?, u32_at(file, 8)?) {
            return Err("payload is not an arm64 Mach-O".into());
        }
        let mut payload = Image { file, segments: Vec::new(), chained_fixups: None, symtab: None, dylibs: Vec::new() };
        let mut at = 32;
        for _ in 0..u32_at(file, 16)? {
            let (cmd, size) = (u32_at(file, at)?, u32_at(file, at + 4)? as usize);
            match cmd {
                LC_SEGMENT_64 => {
                    let name = file.get(at + 8..at + 24).ok_or_else(truncated)?;
                    payload.segments.push(Segment {
                        name: String::from_utf8_lossy(name).trim_end_matches('\0').to_string(),
                        vmaddr: u64_at(file, at + 24)?,
                        vmsize: u64_at(file, at + 32)?,
                        fileoff: u64_at(file, at + 40)?,
                        filesize: u64_at(file, at + 48)?,
                        initprot: u32_at(file, at + 60)? as i32,
                    });
                }
                LC_SYMTAB => {
                    payload.symtab =
                        Some((u32_at(file, at + 8)? as usize, u32_at(file, at + 12)? as usize, u32_at(file, at + 16)? as usize));
                }
                LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LOAD_UPWARD_DYLIB => {
                    payload.dylibs.push(cstr_at(file, at + u32_at(file, at + 8)? as usize)?.to_string());
                }
                LC_DYLD_CHAINED_FIXUPS => {
                    payload.chained_fixups = Some((u32_at(file, at + 8)? as usize, u32_at(file, at + 12)? as usize));
                }
                LC_DYLD_INFO_ONLY if u32_at(file, at + 12)? != 0 || u32_at(file, at + 20)? != 0 => {
                    return Err("payload uses classic dyld info fixups; only chained fixups are supported".into());
                }
                _ => {}
            }
            at += size;
        }
        Ok(payload)
    }

    fn mapped(&self) -> impl Iterator<Item = &Segment> {
        self.segments.iter().filter(|s| s.name != "__PAGEZERO" && s.name != "__LINKEDIT" && s.vmsize > 0)
    }

    /// Where the Mach-O header sits; everything else is relative to it.
    fn base(&self) -> u64 {
        self.mapped().map(|s| s.vmaddr).min().unwrap_or(0)
    }

    /// Mapped segments with their offsets from the image start.
    pub fn layout(&self) -> impl Iterator<Item = (&Segment, u64)> {
        let base = self.base();
        self.mapped().map(move |s| (s, s.vmaddr - base))
    }

    pub fn size(&self) -> u64 {
        let base = self.base();
        self.mapped().map(|s| s.vmaddr + s.vmsize - base).max().unwrap_or(0)
    }

    /// Offset from the image start of an exported symbol (C name, leading underscore included).
    pub fn symbol(&self, name: &str) -> Result<u64, String> {
        let (symoff, nsyms, stroff) = self.symtab.ok_or("payload has no symbol table")?;
        for i in 0..nsyms {
            let at = symoff + i * 16;
            let n_type = *self.file.get(at + 4).ok_or_else(truncated)?;
            // N_SECT: defined in a section
            if n_type & 0x0E == 0x0E && cstr_at(self.file, stroff + u32_at(self.file, at)? as usize)? == name {
                return Ok(u64_at(self.file, at + 8)? - self.base());
            }
        }
        Err(format!("payload doesn't export {name}"))
    }

    /// The image as it must appear at `load_address`. `resolve` maps an imported C symbol (without
    /// the leading underscore) to its address.
    pub fn image(&self, load_address: u64, resolve: impl Fn(&str) -> Option<u64>) -> Result<Vec<u8>, String> {
        let mut image = vec![0u8; self.size() as usize];
        for (segment, offset) in self.layout() {
            let (from, len, to) = (segment.fileoff as usize, segment.filesize as usize, offset as usize);
            image[to..to + len].copy_from_slice(self.file.get(from..from + len).ok_or_else(truncated)?);
        }
        if let Some((dataoff, datasize)) = self.chained_fixups {
            let fixups = self.file.get(dataoff..dataoff + datasize).ok_or_else(truncated)?;
            self.apply_fixups(&mut image, fixups, load_address, resolve)?;
        }
        Ok(image)
    }

    fn imports(&self, fixups: &[u8], resolve: impl Fn(&str) -> Option<u64>) -> Result<Vec<u64>, String> {
        let (imports_offset, symbols_offset) = (u32_at(fixups, 8)? as usize, u32_at(fixups, 12)? as usize);
        let (count, format) = (u32_at(fixups, 16)? as usize, u32_at(fixups, 20)?);
        if u32_at(fixups, 24)? != 0 {
            return Err("compressed import names aren't supported".into());
        }
        (0..count)
            .map(|i| {
                let (name_offset, weak, addend) = match format {
                    1 => {
                        let e = u32_at(fixups, imports_offset + i * 4)?;
                        (e >> 9, e >> 8 & 1 == 1, 0)
                    }
                    2 => {
                        let e = u32_at(fixups, imports_offset + i * 8)?;
                        (e >> 9, e >> 8 & 1 == 1, u32_at(fixups, imports_offset + i * 8 + 4)? as i32 as i64 as u64)
                    }
                    3 => {
                        let e = u64_at(fixups, imports_offset + i * 16)?;
                        ((e >> 32) as u32, e >> 16 & 1 == 1, u64_at(fixups, imports_offset + i * 16 + 8)?)
                    }
                    _ => return Err(format!("unsupported import format {format}")),
                };
                let name = cstr_at(fixups, symbols_offset + name_offset as usize)?;
                match resolve(name.strip_prefix('_').unwrap_or(name)) {
                    Some(address) => Ok(address.wrapping_add(addend)),
                    None if weak => Ok(0),
                    None => Err(format!("can't resolve {name}")),
                }
            })
            .collect()
    }

    fn apply_fixups(
        &self,
        image: &mut [u8],
        fixups: &[u8],
        load_address: u64,
        resolve: impl Fn(&str) -> Option<u64>,
    ) -> Result<(), String> {
        if u32_at(fixups, 0)? != 0 {
            return Err("unknown chained fixups version".into());
        }
        let imports = self.imports(fixups, resolve)?;
        let base = self.base();
        let starts = u32_at(fixups, 4)? as usize;
        for segment in 0..u32_at(fixups, starts)? as usize {
            let info = u32_at(fixups, starts + 4 + segment * 4)? as usize;
            if info == 0 {
                continue;
            }
            let at = starts + info;
            let (page_size, format) = (u16_at(fixups, at + 4)? as u64, u16_at(fixups, at + 6)?);
            let segment_offset = u64_at(fixups, at + 8)?;
            if format != DYLD_CHAINED_PTR_64 && format != DYLD_CHAINED_PTR_64_OFFSET {
                return Err(format!("unsupported chained pointer format {format}"));
            }
            for page in 0..u16_at(fixups, at + 20)? as u64 {
                let start = u16_at(fixups, at + 22 + page as usize * 2)?;
                if start == DYLD_CHAINED_PTR_START_NONE {
                    continue;
                }
                let mut offset = (segment_offset + page * page_size + start as u64) as usize;
                loop {
                    let raw = u64_at(image, offset)?;
                    let value = if raw >> 63 == 1 {
                        let ordinal = (raw & 0xFF_FFFF) as usize;
                        let addend = raw >> 24 & 0xFF;
                        imports.get(ordinal).ok_or("bind to a missing import")?.wrapping_add(addend)
                    } else {
                        let target = raw & 0xF_FFFF_FFFF;
                        let high8 = (raw >> 36 & 0xFF) << 56;
                        let relative = if format == DYLD_CHAINED_PTR_64 { target - base } else { target };
                        (load_address + relative) | high8
                    };
                    image[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
                    let next = (raw >> 51 & 0xFFF) as usize;
                    if next == 0 {
                        break;
                    }
                    offset += next * 4;
                }
            }
        }
        Ok(())
    }
}

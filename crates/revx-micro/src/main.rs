use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        FileExt::read_exact_at(file, buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut done = 0usize;
        while done < buf.len() {
            let n = file.seek_read(&mut buf[done..], offset.saturating_add(done as u64))?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "failed to fill whole buffer",
                ));
            }
            done += n;
        }
        return Ok(());
    }
    #[cfg(not(any(unix, windows)))]
    {
        use std::io::{Read, Seek, SeekFrom};
        let mut cloned = file.try_clone()?;
        cloned.seek(SeekFrom::Start(offset))?;
        cloned.read_exact(buf)
    }
}

const MAX_FUNCS: usize = 16;
const MAX_WINDOW: usize = 256;
const MAX_INSTS: usize = 32;

fn main() {
    let mut args = env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| "help".into());
    if cmd != "analyze" {
        eprintln!("revx-micro analyze <elf>");
        std::process::exit(2);
    }
    let path = args.next().expect("path");
    if let Err(e) = analyze(Path::new(&path)) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn analyze(path: &Path) -> Result<(), String> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    let size = meta.len() as usize;
    if size < 64 {
        return Err("file too small".into());
    }

    let mut ehdr = [0u8; 64];
    read_exact_at(&file, &mut ehdr, 0).map_err(|e| e.to_string())?;
    if &ehdr[0..4] != b"\x7fELF" {
        return Err("not ELF".into());
    }
    if ehdr[4] != 2 {
        return Err("only ELF64 supported".into());
    }
    let is_le = ehdr[5] == 1;
    if !is_le {
        return Err("only little-endian supported".into());
    }
    let machine = u16::from_le_bytes([ehdr[18], ehdr[19]]);
    let arch = match machine {
        0xb7 => "arm64",
        0x3e => "x64",
        _ => "unknown",
    };
    let e_shoff = u64::from_le_bytes(ehdr[40..48].try_into().unwrap());
    let e_shentsize = u16::from_le_bytes([ehdr[58], ehdr[59]]) as u64;
    let e_shnum = u16::from_le_bytes([ehdr[60], ehdr[61]]) as u64;
    let e_shstrndx = u16::from_le_bytes([ehdr[62], ehdr[63]]) as usize;

    let mut shdrs = Vec::with_capacity(e_shnum as usize);
    for i in 0..e_shnum {
        let mut sh = [0u8; 64];
        let off = e_shoff.saturating_add(i.saturating_mul(e_shentsize));
        read_exact_at(&file, &mut sh, off).map_err(|e| e.to_string())?;
        let sh_type = u32::from_le_bytes(sh[4..8].try_into().unwrap());
        let sh_addr = u64::from_le_bytes(sh[16..24].try_into().unwrap());
        let sh_offset = u64::from_le_bytes(sh[24..32].try_into().unwrap());
        let sh_size = u64::from_le_bytes(sh[32..40].try_into().unwrap());
        let sh_link = u32::from_le_bytes(sh[40..44].try_into().unwrap());
        let sh_entsize = u64::from_le_bytes(sh[56..64].try_into().unwrap());
        shdrs.push((sh_type, sh_addr, sh_offset, sh_size, sh_link, sh_entsize));
    }

    let mut text_sections: Vec<(u64, u64, u64)> = Vec::new();
    for &(sh_type, sh_addr, sh_offset, sh_size, _, _) in &shdrs {
        if sh_type == 1 && sh_size > 0 {
            text_sections.push((sh_addr, sh_offset, sh_size));
        }
    }

    let mut exports: Vec<(u64, String)> = Vec::new();
    for &(sh_type, _, sh_offset, sh_size, sh_link, sh_entsize) in &shdrs {
        if sh_type != 2 && sh_type != 11 {
            continue;
        }
        if sh_entsize == 0 || sh_size == 0 {
            continue;
        }
        let count = (sh_size / sh_entsize) as usize;
        let str_off = shdrs.get(sh_link as usize).map(|s| s.2).unwrap_or(0);
        let str_size = shdrs.get(sh_link as usize).map(|s| s.3).unwrap_or(0) as usize;
        let mut strtab = vec![0u8; str_size.min(256 * 1024)];
        if !strtab.is_empty() {
            let _ = read_exact_at(&file, &mut strtab, str_off);
        }
        for i in 0..count {
            if exports.len() >= MAX_FUNCS {
                break;
            }
            let mut ent = [0u8; 24];
            let off = sh_offset.saturating_add((i as u64).saturating_mul(sh_entsize));
            if read_exact_at(&file, &mut ent, off).is_err() {
                break;
            }
            let st_name = u32::from_le_bytes(ent[0..4].try_into().unwrap()) as usize;
            let st_info = ent[4];
            let st_value = u64::from_le_bytes(ent[8..16].try_into().unwrap());
            let bind = st_info >> 4;
            let typ = st_info & 0xf;
            if st_value == 0 || typ != 2 {
                continue;
            }
            if bind != 1 && bind != 2 {
                continue;
            }
            let name = read_cstr(&strtab, st_name);
            if name.is_empty() || name.starts_with('$') {
                continue;
            }
            exports.push((st_value, name));
        }
        if exports.len() >= MAX_FUNCS {
            break;
        }
    }
    let _ = e_shstrndx;

    let mut functions = Vec::new();
    for (addr, name) in exports.into_iter().take(MAX_FUNCS) {
        let Some(window) = read_window(&file, &text_sections, addr, MAX_WINDOW) else {
            continue;
        };
        let insts = if arch == "arm64" {
            count_arm64_insts(&window)
        } else if arch == "x86_64" {
            count_x64_insts(&window)
        } else {
            0
        };
        let inst_size = if arch == "arm64" {
            insts.saturating_mul(4)
        } else {
            window.len()
        };
        functions.push(format!(
            "{{\"name\":{},\"address\":{},\"size\":{},\"insts\":{}}}",
            json_str(&name),
            addr,
            inst_size,
            insts
        ));
    }

    let mut out = String::new();
    out.push_str("{\"tool\":\"revx-micro\",\"architecture\":");
    out.push_str(&json_str(arch));
    out.push_str(",\"function_count\":");
    out.push_str(&functions.len().to_string());
    out.push_str(",\"functions\":[");
    out.push_str(&functions.join(","));
    out.push_str("]}\n");
    std::io::stdout()
        .lock()
        .write_all(out.as_bytes())
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn read_cstr(buf: &[u8], off: usize) -> String {
    if off >= buf.len() {
        return String::new();
    }
    let end = buf[off..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| off + p)
        .unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[off..end]).into_owned()
}

fn read_window(
    file: &File,
    sections: &[(u64, u64, u64)],
    addr: u64,
    max_len: usize,
) -> Option<Vec<u8>> {
    for &(start, file_off, size) in sections {
        if addr < start || addr >= start.saturating_add(size) {
            continue;
        }
        let offset = addr - start;
        let remain = size.saturating_sub(offset) as usize;
        let len = remain.min(max_len);
        if len == 0 {
            return None;
        }
        let mut buf = vec![0u8; len];
        read_exact_at(file, &mut buf, file_off.saturating_add(offset)).ok()?;
        return Some(buf);
    }
    None
}

fn count_arm64_insts(bytes: &[u8]) -> usize {
    let mut n = 0usize;
    let mut off = 0usize;
    while off + 4 <= bytes.len() && n < MAX_INSTS {
        let w = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        n += 1;
        off += 4;
        if is_arm64_terminal(w) {
            break;
        }
    }
    n
}

fn is_arm64_terminal(w: u32) -> bool {
    if w == 0xd65f03c0 {
        return true;
    }
    if (w & 0xfc000000) == 0x14000000 {
        return true;
    }
    if (w & 0xfffffc1f) == 0xd61f0000 {
        return true;
    }
    false
}

const X64_ONE_BYTE: [bool; 256] = x64_one_byte_table();
const X64_PREFIXES: [bool; 256] = x64_prefix_table();

const fn x64_prefix_table() -> [bool; 256] {
    let mut t = [false; 256];
    let mut i = 0;
    while i < 256 {
        t[i] = matches!(
            i,
            0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 | 0x66 | 0x67
        );
        i += 1;
    }
    t
}

const fn x64_one_byte_table() -> [bool; 256] {
    let mut t = [false; 256];
    let one_byte: &[u8] = &[
        0x06, 0x07, 0x0E, 0x16, 0x17, 0x1E, 0x1F, 0x27, 0x2F, 0x37, 0x3F, 0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52,
        0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61,
        0x62, 0x63, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x90, 0x9B, 0x9C, 0x9D, 0x9E,
        0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xC3, 0xC9, 0xCB,
        0xF5, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE,
    ];
    let mut i = 0;
    while i < one_byte.len() {
        t[one_byte[i] as usize] = true;
        i += 1;
    }
    t
}

const X64_MODRM_RM_ONLY: [bool; 8] = [true, true, true, false, true, false, false, false];

#[allow(
    clippy::if_same_then_else,
    clippy::manual_range_contains,
    clippy::match_like_matches_macro
)]
fn count_x64_insts(bytes: &[u8]) -> usize {
    let mut n = 0usize;
    let mut off = 0usize;
    while off < bytes.len() && n < MAX_INSTS {
        let start = off;
        let mut p = off;
        while p < bytes.len() && X64_PREFIXES[bytes[p] as usize] {
            p += 1;
        }
        if p >= bytes.len() {
            break;
        }
        let opcode = bytes[p] as usize;
        p += 1;

        if opcode == 0x0F {
            if p >= bytes.len() {
                break;
            }
            let second = bytes[p] as usize;
            p += 1;
            p += x64_modrm_len_after_0f(second, bytes, p);
            if (0x80..=0x8F).contains(&second) {
                p += 4;
            }
        } else if X64_ONE_BYTE[opcode] {
            if (0x40..=0x4F).contains(&opcode) {
                if p < bytes.len() {
                    p += 1;
                }
            } else if opcode == 0x68 {
                p += 4;
            } else if matches!(opcode, 0x6A | 0xA8 | 0xA9) {
                p += 1;
            } else if (0x50..=0x5F).contains(&opcode)
                || matches!(
                    opcode,
                    0x90 | 0x9C | 0x9D | 0x9E | 0x9B | 0xC3 | 0xC9 | 0xCB
                )
            {
            } else if matches!(opcode, 0x69 | 0x6B) {
                p += 1 + x64_modrm_len(bytes, p);
                p += 4;
            } else if matches!(
                opcode,
                0x6C | 0x6D
                    | 0x6E
                    | 0x6F
                    | 0xA4
                    | 0xA5
                    | 0xA6
                    | 0xA7
                    | 0xAA
                    | 0xAB
                    | 0xAC
                    | 0xAD
                    | 0xAE
                    | 0xAF
            ) {
            }
        } else if (0x00..=0x3F).contains(&opcode) {
            let group = opcode >> 3;
            p += x64_modrm_len(bytes, p);
            if group == 0x1 && (opcode & 1) == 0 {
                p += 1;
            } else if group == 0x1 && (opcode & 1) == 1 {
                p += 4;
            }
        } else if (0x70..=0x7F).contains(&opcode) {
            p += 1;
        } else if (0x80..=0x83).contains(&opcode) {
            let imm = if opcode == 0x83 { 1 } else { 4 };
            p += x64_modrm_len(bytes, p);
            p += imm;
        } else if (0x84..=0x8F).contains(&opcode) {
            p += x64_modrm_len(bytes, p);
        } else if (0xB0..=0xB7).contains(&opcode) {
            p += 1;
        } else if (0xB8..=0xBF).contains(&opcode) {
            p += 8;
        } else if (0xC0..=0xC1).contains(&opcode) {
            p += x64_modrm_len(bytes, p);
            p += 1;
        } else if (0xC2..=0xC3).contains(&opcode) {
            if opcode == 0xC2 {
                p += 2;
            }
        } else if matches!(opcode, 0xC6) {
            p += x64_modrm_len(bytes, p);
            p += 4;
        } else if matches!(opcode, 0xC7) {
            p += x64_modrm_len(bytes, p);
            p += 1;
        } else if (0xC8..=0xCF).contains(&opcode) {
            if matches!(opcode, 0xC8) {
                p += 4;
            }
        } else if (0xD0..=0xD3).contains(&opcode) {
            p += x64_modrm_len(bytes, p);
        } else if (0xD8..=0xDF).contains(&opcode) {
            p += x64_modrm_len(bytes, p);
        } else if (0xE0..=0xE2).contains(&opcode) {
            p += 1;
        } else if matches!(opcode, 0xE3) {
            p += 1;
        } else if (0xE4..=0xE7).contains(&opcode) {
            p += 1;
        } else if matches!(opcode, 0xE8 | 0xE9) {
            p += 4;
        } else if matches!(opcode, 0xEA) {
            p += 6;
        } else if matches!(opcode, 0xEB) {
            p += 1;
        } else if (0xEC..=0xEF).contains(&opcode) {
        } else if (0xF1..=0xF7).contains(&opcode) {
            p += x64_modrm_len(bytes, p);
        }

        let consumed = p.saturating_sub(start).max(1).min(bytes.len() - start);
        off += consumed;
        n += 1;
        if x64_is_terminal(bytes, start, consumed) {
            break;
        }
    }
    n
}

fn x64_modrm_len(bytes: &[u8], p: usize) -> usize {
    if p >= bytes.len() {
        return 0;
    }
    let modrm = bytes[p];
    let mode = (modrm >> 6) & 0x3;
    let rm = (modrm & 0x7) as usize;
    match mode {
        0x3 => 1,
        0x0 => {
            if X64_MODRM_RM_ONLY[rm] {
                1
            } else if rm == 4 {
                1 + x64_sib_len(bytes, p + 1)
            } else {
                1
            }
        }
        0x1 => {
            let base = if rm == 4 {
                1 + x64_sib_len(bytes, p + 1)
            } else {
                1
            };
            base + 1
        }
        0x2 => {
            let base = if rm == 4 {
                1 + x64_sib_len(bytes, p + 1)
            } else {
                1
            };
            base + 4
        }
        _ => 1,
    }
}

fn x64_sib_len(bytes: &[u8], p: usize) -> usize {
    if p >= bytes.len() {
        return 0;
    }
    let sib = bytes[p];
    let base = (sib & 0x7) as usize;
    if base == 5 { 4 } else { 0 }
}

fn x64_modrm_len_after_0f(second: usize, bytes: &[u8], p: usize) -> usize {
    let needs_modrm = (0x00..=0x03).contains(&second)
        || (0x10..=0x17).contains(&second)
        || (0x20..=0x23).contains(&second)
        || (0x28..=0x2F).contains(&second)
        || (0x40..=0x4F).contains(&second)
        || (0x51..=0x5F).contains(&second)
        || (0x60..=0x6F).contains(&second)
        || (0x70..=0x73).contains(&second)
        || (0x90..=0x9F).contains(&second)
        || (0xA3..=0xA7).contains(&second)
        || (0xAF..=0xB7).contains(&second)
        || (0xB9..=0xBF).contains(&second)
        || (0xC0..=0xC1).contains(&second)
        || (0xC4..=0xC5).contains(&second)
        || (0xC8..=0xCF).contains(&second)
        || (0xD1..=0xD7).contains(&second)
        || (0xDB..=0xDF).contains(&second)
        || (0xE0..=0xE7).contains(&second)
        || (0xF0..=0xF7).contains(&second);
    if needs_modrm {
        x64_modrm_len(bytes, p)
    } else {
        0
    }
}

fn x64_is_terminal(bytes: &[u8], start: usize, len: usize) -> bool {
    if len == 0 {
        return false;
    }
    let op = bytes[start];
    let mut p = start + 1;
    while p < start + len && X64_PREFIXES[bytes[p] as usize] {
        p += 1;
    }
    if p >= start + len {
        return false;
    }
    let code = bytes[p];
    code == 0xC3
        || code == 0xC2
        || code == 0xCB
        || code == 0xCA
        || (code == 0x0F && p + 1 < start + len && bytes[p + 1] >= 0x80 && bytes[p + 1] <= 0x8F)
        || (code == 0xE9)
        || (code == 0xEA)
        || (code == 0xEB)
        || (code == 0xFF && p + 1 < start + len && (bytes[p + 1] >> 3) & 0x7 == 4)
        || (code == 0xFF && p + 1 < start + len && (bytes[p + 1] >> 3) & 0x7 == 5)
        || (op == 0xC3)
}

fn json_str(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for ch in s.chars() {
        match ch {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if c.is_control() => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

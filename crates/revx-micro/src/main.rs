use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        return FileExt::read_exact_at(file, buf, offset);
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
        } else {
            0
        };
        functions.push(format!(
            "{{\"name\":{},\"address\":{},\"size\":{},\"insts\":{}}}",
            json_str(&name),
            addr,
            insts.saturating_mul(4),
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
        read_exact_at(&file, &mut buf, file_off.saturating_add(offset))
            .ok()?;
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

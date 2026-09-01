//! Bridge between revx and the vendored Ghidra decompiler core.
//!
//! Contract (see third_party/ghidra-decompiler/README.md):
//! 1. revx recovers function boundaries from its workspace
//! 2. this module maps vaddr→file bytes via ELF program headers and emits a
//!    `<binaryimage>` XML (hex bytechunk, whole executable segment so control
//!    flow and callees resolve)
//! 3. drives the console decompiler: load → load addr → decompile → print C
//! 4. returns the C text; diagnostics arrive on unbuffered stderr

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub struct GhidraBridge {
    pub decomp_bin: PathBuf,
    pub sleigh_home: PathBuf,
}

pub struct GhidraInput {
    /// ELF path bytes are read from (same file the workspace analyzed)
    pub image_path: String,
    /// function virtual address
    pub address: u64,
    /// function name for the Ghidra symbol
    pub name: String,
}

fn find_decomp_bin() -> Option<PathBuf> {
    // 1. env override
    if let Ok(p) = std::env::var("REVX_GHIDRA_DECOMP")
        && !p.is_empty()
    {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Some(path);
        }
    }
    // 2. repo-relative vendored build output (vendored source root or workspace)
    let cwd = std::env::current_dir().ok()?;
    let mut dir = Some(cwd.as_path());
    while let Some(d) = dir {
        let vendored = d.join("third_party/ghidra-decompiler");
        for candidate in [
            vendored.join("cpp/decomp_opt"),
            vendored.join("build/decomp_opt"),
        ] {
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        dir = d.parent();
    }
    // 3. executable dir (release layout: bin/ next to revx)
    if let Ok(exe) = std::env::current_exe()
        && let Some(parent) = exe.parent()
    {
        let candidate = parent.join("decomp_opt");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn sleigh_home() -> PathBuf {
    if let Ok(p) = std::env::var("REVX_GHIDRA_SLEIGH_HOME")
        && !p.is_empty()
    {
        return PathBuf::from(p);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".revx/ghidra")
}

impl GhidraBridge {
    pub fn discover() -> Option<Self> {
        let decomp_bin = find_decomp_bin()?;
        Some(Self {
            decomp_bin,
            sleigh_home: sleigh_home(),
        })
    }

    /// Ensure the AARCH64 sla + spec XMLs exist under sleigh_home, compiling
    /// them from the vendored upstream layout on first use.
    pub fn ensure_specs(&self) -> Result<(), String> {
        let lang_dir = self
            .sleigh_home
            .join("Ghidra/Processors/AARCH64/data/languages");
        if lang_dir.join("AARCH64.sla").is_file() {
            return Ok(());
        }
        // source spec dir: vendored spec mirror or upstream checkout via env
        let src_dir = std::env::var("REVX_GHIDRA_SPECS_SRC")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                self.decomp_bin
                    .parent()
                    .unwrap_or(Path::new("."))
                    .ancestors()
                    .find_map(|p| {
                        let c = p.join("third_party/ghidra-decompiler/specs/AARCH64");
                        c.is_dir().then_some(c)
                    })
                    .ok_or_else(|| {
                        "AARCH64 sleigh specs not found; set REVX_GHIDRA_SPECS_SRC".to_string()
                    })
                    .expect("specs dir")
            });
        std::fs::create_dir_all(&lang_dir).map_err(|e| e.to_string())?;
        for file in ["AARCH64.ldefs", "AARCH64.pspec", "AARCH64.cspec"] {
            std::fs::copy(src_dir.join(file), lang_dir.join(file))
                .map_err(|e| format!("copy {file}: {e}"))?;
        }
        let sleigh_bin = self.decomp_bin.with_file_name("sleigh_opt");
        let out = Command::new(&sleigh_bin)
            .arg(src_dir.join("AARCH64.slaspec"))
            .arg(lang_dir.join("AARCH64.sla"))
            .output()
            .map_err(|e| format!("run sleigh_opt: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "sleigh_opt failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(())
    }

    /// Emit the binaryimage XML: one hex bytechunk covering from the segment
    /// base through the end of the executable mapping (function + callees).
    fn write_image_xml(&self, input: &GhidraInput, out_path: &Path) -> Result<(), String> {
        let bytes = std::fs::read(&input.image_path).map_err(|e| e.to_string())?;
        let (seg_file_off, seg_vaddr, seg_filesz) = elf_exec_segment(&bytes, input.address)
            .ok_or_else(|| "function address outside any executable PT_LOAD".to_string())?;
        let start = seg_file_off + (input.address - seg_vaddr) as usize;
        let end = seg_file_off + seg_filesz as usize;
        let code = bytes
            .get(start..end.min(bytes.len()))
            .ok_or_else(|| "segment bytes out of range".to_string())?;
        let xml = format!(
            "<binaryimage arch=\"AARCH64:LE:64:v8A\">\n  <bytechunk space=\"ram\" offset=\"{:#x}\" fileoffset=\"0\" size=\"{}\">{}</bytechunk>\n</binaryimage>\n",
            input.address,
            code.len(),
            hex_encode(code)
        );
        std::fs::write(out_path, xml).map_err(|e| e.to_string())
    }

    /// Drive the console decompiler for one function; returns C text.
    pub fn decompile_function(&self, input: &GhidraInput) -> Result<String, String> {
        self.ensure_specs()?;
        let tmp = std::env::temp_dir();
        let xml_path = tmp.join(format!("revx_ghidra_{}.xml", std::process::id()));
        let script_path = tmp.join(format!("revx_ghidra_{}.script", std::process::id()));
        self.write_image_xml(input, &xml_path)?;

        let script = format!(
            "load file {xml}\nload addr {addr:#x} {name}\ndecompile\nprint C\nquit\n",
            xml = xml_path.display(),
            addr = input.address,
            name = input.name,
        );
        std::fs::write(&script_path, script).map_err(|e| e.to_string())?;

        let script_in = std::fs::File::open(&script_path).map_err(|e| e.to_string())?;
        let child = Command::new(&self.decomp_bin)
            .env("SLEIGHHOME", &self.sleigh_home)
            .stdin(Stdio::from(script_in))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn {}: {e}", self.decomp_bin.display()))?;
        let output = child.wait_with_output().map_err(|e| e.to_string())?;
        let _ = std::fs::remove_file(&xml_path);
        let _ = std::fs::remove_file(&script_path);
        if !output.status.success() {
            return Err(format!(
                "decomp_opt exited {:?}; stderr: {} (see third_party/ghidra-decompiler/README.md)",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        // console output is routed to unbuffered stderr (VENDORED.md mod #4),
        // while `print C` body flows to the same stream; join both.
        let mut transcript = String::from_utf8_lossy(&output.stdout).into_owned();
        transcript.push_str(&String::from_utf8_lossy(&output.stderr));
        let c_text = extract_print_c(&transcript).ok_or_else(|| {
            format!(
                "decompilation produced no C output (function creation failed?); transcript tail: {}",
                transcript.chars().rev().take(400).collect::<String>().chars().rev().collect::<String>()
            )
        })?;
        Ok(c_text)
    }
}

fn hex_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Locate the executable PT_LOAD containing `vaddr`; returns
/// (file_offset, vaddr, filesz) of that segment.
fn elf_exec_segment(bytes: &[u8], vaddr: u64) -> Option<(usize, u64, u64)> {
    if bytes.get(0..4)? != b"\x7fELF" {
        return None;
    }
    let phoff = u64::from_le_bytes(bytes.get(0x20..0x28)?.try_into().ok()?) as usize;
    let phentsize = u16::from_le_bytes(bytes.get(0x36..0x38)?.try_into().ok()?) as usize;
    let phnum = u16::from_le_bytes(bytes.get(0x38..0x3a)?.try_into().ok()?) as usize;
    for i in 0..phnum {
        let base = phoff + i * phentsize;
        let p_type = u32::from_le_bytes(bytes.get(base..base + 4)?.try_into().ok()?);
        let p_flags = u32::from_le_bytes(bytes.get(base + 4..base + 8)?.try_into().ok()?);
        let p_offset = u64::from_le_bytes(bytes.get(base + 8..base + 16)?.try_into().ok()?);
        let p_vaddr = u64::from_le_bytes(bytes.get(base + 16..base + 24)?.try_into().ok()?);
        let p_filesz = u64::from_le_bytes(bytes.get(base + 32..base + 40)?.try_into().ok()?);
        if p_type == 1 && (p_flags & 1) != 0 && p_vaddr <= vaddr && vaddr < p_vaddr + p_filesz {
            return Some((p_offset as usize, p_vaddr, p_filesz));
        }
    }
    None
}

/// Pull the C text out of the console transcript: everything after the
/// "print C" prompt echo until the final "[decomp]> quit" echo.
fn extract_print_c(transcript: &str) -> Option<String> {
    let marker = "[decomp]> print C\n";
    let start = transcript.find(marker)? + marker.len();
    let rest = &transcript[start..];
    let end = rest.find("[decomp]> quit").unwrap_or(rest.len());
    let c = rest[..end].trim().to_string();
    if c.is_empty() { None } else { Some(c) }
}

/// Convenience used by the CLI: returns Some(c_text) when the ghidra engine
/// is available, None when the vendored binary is absent (caller falls back).
pub fn try_decompile(image_path: &str, address: u64, name: &str) -> Result<Option<String>, String> {
    let Some(bridge) = GhidraBridge::discover() else {
        return Ok(None);
    };
    let input = GhidraInput {
        image_path: image_path.to_string(),
        address,
        name: sanitize_symbol(name),
    };
    let text = bridge.decompile_function(&input)?;
    Ok(Some(text))
}

fn sanitize_symbol(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() || cleaned.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        format!("revx_fn_{cleaned}")
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elf_exec_segment_finds_text() {
        // minimal ELF with one executable PT_LOAD is enough
        let mut elf = Vec::new();
        elf.extend_from_slice(b"\x7fELF");
        elf.extend_from_slice(&[2u8, 1, 1, 0]); // 64-bit LE, SysV
        elf.extend_from_slice(&[0u8; 8]); // e_ident pad
        elf.extend_from_slice(&2u16.to_le_bytes()); // e_type ET_EXEC
        elf.extend_from_slice(&0xb7u16.to_le_bytes()); // e_machine AARCH64
        elf.extend_from_slice(&1u32.to_le_bytes()); // e_version
        elf.extend_from_slice(&0u64.to_le_bytes()); // e_entry
        elf.extend_from_slice(&64u64.to_le_bytes()); // e_phoff
        elf.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
        elf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        elf.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
        elf.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
        elf.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
        elf.extend_from_slice(&[0u8; 6]); // shentsize/shnum/shstrndx
        while elf.len() < 64 {
            elf.push(0);
        }
        // phdr: type=PT_LOAD(1) flags=RX(5) offset=0x100 vaddr=0x1000 filesz=0x200
        elf.extend_from_slice(&1u32.to_le_bytes());
        elf.extend_from_slice(&5u32.to_le_bytes());
        elf.extend_from_slice(&0x100u64.to_le_bytes());
        elf.extend_from_slice(&0x1000u64.to_le_bytes());
        elf.extend_from_slice(&0u64.to_le_bytes());
        elf.extend_from_slice(&0x200u64.to_le_bytes());
        assert_eq!(elf_exec_segment(&elf, 0x1000), Some((0x100, 0x1000, 0x200)));
        assert_eq!(elf_exec_segment(&elf, 0x2000), None);
    }

    #[test]
    fn sanitize_symbol() {
        assert_eq!(super::sanitize_symbol("decrypt"), "decrypt");
        assert_eq!(
            super::sanitize_symbol("Java_a_b_decrypt"),
            "Java_a_b_decrypt"
        );
        assert_eq!(super::sanitize_symbol("weird name!"), "weird_name_");
        assert_eq!(super::sanitize_symbol("0addr"), "revx_fn_0addr");
    }

    #[test]
    fn extract_print_c_basic() {
        let t =
            "[decomp]> load file x\n[decomp]> print C\n\nint f() { return 0; }\n[decomp]> quit\n";
        assert_eq!(extract_print_c(t).as_deref(), Some("int f() { return 0; }"));
        assert_eq!(extract_print_c("no marker"), None);
    }
}

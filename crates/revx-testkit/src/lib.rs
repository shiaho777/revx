use revx_core::{Architecture, BinaryFormat};
use std::fs;
use std::path::PathBuf;

pub struct Case {
    pub id: &'static str,
    pub format: BinaryFormat,
    pub arch: Architecture,
    pub bytes: Vec<u8>,
}

pub fn arm64_code_branch_ret() -> Vec<u8> {
    let mut code = Vec::new();
    code.extend_from_slice(&0x34000040u32.to_le_bytes());
    code.extend_from_slice(&0x52800000u32.to_le_bytes());
    code.extend_from_slice(&0xd65f03c0u32.to_le_bytes());
    code.extend_from_slice(&0x52800020u32.to_le_bytes());
    code.extend_from_slice(&0xd65f03c0u32.to_le_bytes());
    code
}

pub fn x64_code_branch_ret() -> Vec<u8> {
    vec![
        0x89, 0xff, 0x85, 0xff, 0x74, 0x03, 0x31, 0xc0, 0xc3, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3,
    ]
}

pub fn arm64_code_args_call() -> Vec<u8> {
    let mut code = Vec::new();
    let insts = [
        0xa9bf7bfdu32,
        0x910003fd,
        0xd10043ff,
        0xb9001fe0,
        0x7100001f,
        0x54000060,
        0x9400000a,
        0x94000002,
        0x52800000,
        0xf94007fe,
        0x910043ff,
        0xa8c17bfd,
        0xd65f03c0,
    ];
    for inst in insts {
        code.extend_from_slice(&inst.to_le_bytes());
    }
    code.extend_from_slice(&[0; 12]);
    code.extend_from_slice(&0x11000400u32.to_le_bytes());
    code.extend_from_slice(&0xd65f03c0u32.to_le_bytes());
    code
}

pub fn x64_code_args_call() -> Vec<u8> {
    let mut code = Vec::new();
    code.extend_from_slice(&[0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10]);
    code.extend_from_slice(&[0x89, 0x7d, 0xfc]);
    code.extend_from_slice(&[0x83, 0xff, 0x00]);
    code.extend_from_slice(&[0x74, 0x05]);
    code.extend_from_slice(&[0xe8, 0x1b, 0x00, 0x00, 0x00]);
    code.extend_from_slice(&[0xeb, 0x02]);
    code.extend_from_slice(&[0xb8, 0x00, 0x00, 0x00, 0x00]);
    code.extend_from_slice(&[0xc9, 0xc3]);
    code.extend_from_slice(&[0; 0x12]);
    code.extend_from_slice(&[0x8d, 0x47, 0x01]);
    code.extend_from_slice(&[0xc3]);
    code
}

fn align(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

pub fn elf64(code: &[u8], machine: u16, entry: u64) -> Vec<u8> {
    let ehdr_size = 64usize;
    let phdr_size = 56usize;
    let shdr_size = 64usize;
    let phoff = ehdr_size;
    let code_off = align(phoff + phdr_size, 16);
    let code_addr = entry;
    let shstrtab = b"\0.shstrtab\0.text\0.symtab\0.strtab\0";
    let strtab = b"\0main\0";
    let symtab_entsize = 24usize;
    let mut symtab = vec![0u8; symtab_entsize];
    symtab.extend_from_slice(&1u32.to_le_bytes());
    symtab.push(0x12);
    symtab.push(0);
    symtab.extend_from_slice(&1u16.to_le_bytes());
    symtab.extend_from_slice(&code_addr.to_le_bytes());
    symtab.extend_from_slice(&(code.len() as u64).to_le_bytes());

    let mut out = vec![0u8; code_off];
    out[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    out[4] = 2;
    out[5] = 1;
    out[6] = 1;
    out[16..18].copy_from_slice(&2u16.to_le_bytes());
    out[18..20].copy_from_slice(&machine.to_le_bytes());
    out[20..24].copy_from_slice(&1u32.to_le_bytes());
    out[24..32].copy_from_slice(&entry.to_le_bytes());
    out[32..40].copy_from_slice(&(phoff as u64).to_le_bytes());
    out[52..54].copy_from_slice(&(ehdr_size as u16).to_le_bytes());
    out[54..56].copy_from_slice(&(phdr_size as u16).to_le_bytes());
    out[56..58].copy_from_slice(&1u16.to_le_bytes());
    out[58..60].copy_from_slice(&(shdr_size as u16).to_le_bytes());

    out[phoff..phoff + 4].copy_from_slice(&1u32.to_le_bytes());
    out[phoff + 4..phoff + 8].copy_from_slice(&5u32.to_le_bytes());
    out[phoff + 8..phoff + 16].copy_from_slice(&(code_off as u64).to_le_bytes());
    out[phoff + 16..phoff + 24].copy_from_slice(&code_addr.to_le_bytes());
    out[phoff + 24..phoff + 32].copy_from_slice(&code_addr.to_le_bytes());
    out[phoff + 32..phoff + 40].copy_from_slice(&(code.len() as u64).to_le_bytes());
    out[phoff + 40..phoff + 48].copy_from_slice(&(code.len() as u64).to_le_bytes());
    out[phoff + 48..phoff + 56].copy_from_slice(&0x1000u64.to_le_bytes());

    out.extend_from_slice(code);
    let sym_off = out.len();
    out.extend_from_slice(&symtab);
    let str_off = out.len();
    out.extend_from_slice(strtab);
    let shstr_off = out.len();
    out.extend_from_slice(shstrtab);
    let shoff = align(out.len(), 8);
    out.resize(shoff, 0);

    let mut write_shdr = |name: u32,
                          kind: u32,
                          flags: u64,
                          addr: u64,
                          off: u64,
                          size: u64,
                          link: u32,
                          info: u32,
                          addralign: u64,
                          entsize: u64| {
        let mut h = vec![0u8; shdr_size];
        h[0..4].copy_from_slice(&name.to_le_bytes());
        h[4..8].copy_from_slice(&kind.to_le_bytes());
        h[8..16].copy_from_slice(&flags.to_le_bytes());
        h[16..24].copy_from_slice(&addr.to_le_bytes());
        h[24..32].copy_from_slice(&off.to_le_bytes());
        h[32..40].copy_from_slice(&size.to_le_bytes());
        h[40..44].copy_from_slice(&link.to_le_bytes());
        h[44..48].copy_from_slice(&info.to_le_bytes());
        h[48..56].copy_from_slice(&addralign.to_le_bytes());
        h[56..64].copy_from_slice(&entsize.to_le_bytes());
        out.extend_from_slice(&h);
    };

    write_shdr(0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    write_shdr(
        10,
        1,
        6,
        code_addr,
        code_off as u64,
        code.len() as u64,
        0,
        0,
        16,
        0,
    );
    write_shdr(
        16,
        2,
        0,
        0,
        sym_off as u64,
        symtab.len() as u64,
        3,
        1,
        8,
        symtab_entsize as u64,
    );
    write_shdr(24, 3, 0, 0, str_off as u64, strtab.len() as u64, 0, 0, 1, 0);
    write_shdr(
        1,
        3,
        0,
        0,
        shstr_off as u64,
        shstrtab.len() as u64,
        0,
        0,
        1,
        0,
    );

    out[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
    out[60..62].copy_from_slice(&5u16.to_le_bytes());
    out[62..64].copy_from_slice(&4u16.to_le_bytes());
    out
}

pub fn macho64(code: &[u8], cputype: u32, cpusub: u32, entry: u64) -> Vec<u8> {
    let header_size = 32usize;
    let ncmds = 3u32;
    let seg_cmd_size = 72u32 + 80;
    let unix_cmd_size = 16u32;
    let symtab_cmd_size = 24u32;
    let sizeofcmds = seg_cmd_size + unix_cmd_size + symtab_cmd_size;
    let code_off = align(header_size + sizeofcmds as usize, 16);
    let mut out = vec![0u8; code_off];
    out[0..4].copy_from_slice(&0xfeedfacfu32.to_le_bytes());
    out[4..8].copy_from_slice(&cputype.to_le_bytes());
    out[8..12].copy_from_slice(&cpusub.to_le_bytes());
    out[12..16].copy_from_slice(&2u32.to_le_bytes());
    out[16..20].copy_from_slice(&ncmds.to_le_bytes());
    out[20..24].copy_from_slice(&sizeofcmds.to_le_bytes());
    out[24..28].copy_from_slice(&1u32.to_le_bytes());

    let mut off = header_size;
    out[off..off + 4].copy_from_slice(&0x19u32.to_le_bytes());
    out[off + 4..off + 8].copy_from_slice(&seg_cmd_size.to_le_bytes());
    out[off + 8..off + 24].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
    out[off + 24..off + 32].copy_from_slice(&entry.to_le_bytes());
    out[off + 32..off + 40].copy_from_slice(&((code.len() as u64).max(0x1000)).to_le_bytes());
    out[off + 40..off + 48].copy_from_slice(&(code_off as u64).to_le_bytes());
    out[off + 48..off + 56].copy_from_slice(&(code.len() as u64).to_le_bytes());
    out[off + 56..off + 60].copy_from_slice(&5u32.to_le_bytes());
    out[off + 60..off + 64].copy_from_slice(&5u32.to_le_bytes());
    out[off + 64..off + 68].copy_from_slice(&1u32.to_le_bytes());
    let sect = off + 72;
    out[sect..sect + 16].copy_from_slice(b"__text\0\0\0\0\0\0\0\0\0\0");
    out[sect + 16..sect + 32].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
    out[sect + 32..sect + 40].copy_from_slice(&entry.to_le_bytes());
    out[sect + 40..sect + 48].copy_from_slice(&(code.len() as u64).to_le_bytes());
    out[sect + 48..sect + 52].copy_from_slice(&(code_off as u32).to_le_bytes());
    out[sect + 52..sect + 56].copy_from_slice(&2u32.to_le_bytes());
    off += seg_cmd_size as usize;

    out[off..off + 4].copy_from_slice(&0x5u32.to_le_bytes());
    out[off + 4..off + 8].copy_from_slice(&unix_cmd_size.to_le_bytes());
    out[off + 8..off + 16].copy_from_slice(&entry.to_le_bytes());
    off += unix_cmd_size as usize;

    let strtab = b"\0_main\0";
    let mut nlist = vec![0u8; 16];
    nlist[0..4].copy_from_slice(&1u32.to_le_bytes());
    nlist[4] = 0x0f;
    nlist[5] = 1;
    nlist[8..16].copy_from_slice(&entry.to_le_bytes());
    let symoff = code_off + code.len();
    let stroff = symoff + nlist.len();
    out[off..off + 4].copy_from_slice(&0x2u32.to_le_bytes());
    out[off + 4..off + 8].copy_from_slice(&symtab_cmd_size.to_le_bytes());
    out[off + 8..off + 12].copy_from_slice(&(symoff as u32).to_le_bytes());
    out[off + 12..off + 16].copy_from_slice(&1u32.to_le_bytes());
    out[off + 16..off + 20].copy_from_slice(&(stroff as u32).to_le_bytes());
    out[off + 20..off + 24].copy_from_slice(&(strtab.len() as u32).to_le_bytes());

    out.extend_from_slice(code);
    out.extend_from_slice(&nlist);
    out.extend_from_slice(strtab);
    out
}

pub fn pe64(code: &[u8], machine: u16, entry_rva: u32) -> Vec<u8> {
    let mut dos = vec![0u8; 0x80];
    dos[0] = b'M';
    dos[1] = b'Z';
    dos[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    let pe_off = dos.len();
    let opt_size = 0xf0usize;
    let section_hdr = 40usize;
    let headers = pe_off + 4 + 20 + opt_size + section_hdr;
    let headers_aligned = align(headers, 0x200);
    let code_raw = headers_aligned;
    let code_raw_size = align(code.len(), 0x200);
    let image_size = align(0x1000 + code.len(), 0x1000);

    let mut out = vec![0u8; code_raw + code_raw_size];
    out[..dos.len()].copy_from_slice(&dos);
    out[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
    let coff = pe_off + 4;
    out[coff..coff + 2].copy_from_slice(&machine.to_le_bytes());
    out[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
    out[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());
    out[coff + 18..coff + 20].copy_from_slice(&0x22u16.to_le_bytes());

    let opt = coff + 20;
    out[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
    out[opt + 16..opt + 20].copy_from_slice(&entry_rva.to_le_bytes());
    out[opt + 24..opt + 32].copy_from_slice(&0x140000000u64.to_le_bytes());
    out[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    out[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
    out[opt + 56..opt + 60].copy_from_slice(&(image_size as u32).to_le_bytes());
    out[opt + 60..opt + 64].copy_from_slice(&(headers_aligned as u32).to_le_bytes());
    out[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
    out[opt + 88..opt + 92].copy_from_slice(&0x100000u32.to_le_bytes());
    out[opt + 92..opt + 96].copy_from_slice(&0x1000u32.to_le_bytes());
    out[opt + 96..opt + 100].copy_from_slice(&0x100000u32.to_le_bytes());
    out[opt + 100..opt + 104].copy_from_slice(&0x1000u32.to_le_bytes());
    out[opt + 108..opt + 110].copy_from_slice(&16u16.to_le_bytes());

    let sect = opt + opt_size;
    out[sect..sect + 8].copy_from_slice(b".text\0\0\0");
    out[sect + 8..sect + 12].copy_from_slice(&(code.len() as u32).to_le_bytes());
    out[sect + 12..sect + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    out[sect + 16..sect + 20].copy_from_slice(&(code_raw_size as u32).to_le_bytes());
    out[sect + 20..sect + 24].copy_from_slice(&(code_raw as u32).to_le_bytes());
    out[sect + 36..sect + 40].copy_from_slice(&0x60000020u32.to_le_bytes());
    out[code_raw..code_raw + code.len()].copy_from_slice(code);
    out
}

pub fn all_cases() -> Vec<Case> {
    let x64 = x64_code_branch_ret();
    let a64 = arm64_code_branch_ret();
    vec![
        Case {
            id: "elf_x64",
            format: BinaryFormat::Elf,
            arch: Architecture::X86_64,
            bytes: elf64(&x64, 0x3e, 0x401000),
        },
        Case {
            id: "elf_arm64",
            format: BinaryFormat::Elf,
            arch: Architecture::Arm64,
            bytes: elf64(&a64, 0xb7, 0x401000),
        },
        Case {
            id: "macho_x64",
            format: BinaryFormat::MachO,
            arch: Architecture::X86_64,
            bytes: macho64(&x64, 0x01000007, 3, 0x1000),
        },
        Case {
            id: "macho_arm64",
            format: BinaryFormat::MachO,
            arch: Architecture::Arm64,
            bytes: macho64(&a64, 0x0100000c, 0, 0x1000),
        },
        Case {
            id: "pe_x64",
            format: BinaryFormat::Pe,
            arch: Architecture::X86_64,
            bytes: pe64(&x64, 0x8664, 0x1000),
        },
        Case {
            id: "pe_arm64",
            format: BinaryFormat::Pe,
            arch: Architecture::Arm64,
            bytes: pe64(&a64, 0xaa64, 0x1000),
        },
    ]
}

pub fn elf_args_call_cases() -> Vec<Case> {
    let x64 = x64_code_args_call();
    let a64 = arm64_code_args_call();
    vec![
        Case {
            id: "elf_args_x64",
            format: BinaryFormat::Elf,
            arch: Architecture::X86_64,
            bytes: elf64(&x64, 0x3e, 0x401000),
        },
        Case {
            id: "elf_args_arm64",
            format: BinaryFormat::Elf,
            arch: Architecture::Arm64,
            bytes: elf64(&a64, 0xb7, 0x401000),
        },
    ]
}

pub fn write_temp(case: &Case) -> PathBuf {
    let dir = std::env::temp_dir().join("revx-testkit");
    let _ = fs::create_dir_all(&dir);
    let path = dir.join(format!(
        "{}-{}-{}.bin",
        case.id,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    fs::write(&path, &case.bytes).expect("write fixture");
    path
}

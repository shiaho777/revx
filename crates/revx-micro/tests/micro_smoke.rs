use std::fs;
use std::process::Command;

fn put_u16(buf: &mut [u8], off: usize, value: u16) {
    buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(buf: &mut [u8], off: usize, value: u32) {
    buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(buf: &mut [u8], off: usize, value: u64) {
    buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
}

fn sample_x64_elf() -> Vec<u8> {
    let text_off = 0x1000usize;
    let text_size = 8usize;
    let symtab_off = text_off + text_size;
    let symtab_size = 48usize;
    let strtab_off = symtab_off + symtab_size;
    let strtab = b"\0main\0";
    let shoff = (strtab_off + strtab.len()) as u64;
    let mut buf = vec![0u8; shoff as usize + 4 * 64];

    buf[0..4].copy_from_slice(b"\x7fELF");
    buf[4] = 2;
    buf[5] = 1;
    buf[6] = 1;
    put_u16(&mut buf, 16, 2);
    put_u16(&mut buf, 18, 0x3e);
    put_u32(&mut buf, 20, 1);
    put_u64(&mut buf, 24, 0x400000);
    put_u64(&mut buf, 40, shoff);
    put_u16(&mut buf, 58, 64);
    put_u16(&mut buf, 60, 4);
    put_u16(&mut buf, 62, 3);

    buf[text_off..text_off + text_size]
        .copy_from_slice(&[0x55, 0x48, 0x89, 0xe5, 0x90, 0x90, 0x5d, 0xc3]);

    let sym = symtab_off + 24;
    put_u32(&mut buf, sym, 1);
    buf[sym + 4] = 0x12;
    put_u64(&mut buf, sym + 8, 0x400000);
    put_u64(&mut buf, sym + 16, text_size as u64);

    buf[strtab_off..strtab_off + strtab.len()].copy_from_slice(strtab);

    let sh = shoff as usize;
    let s1 = sh + 64;
    put_u32(&mut buf, s1 + 4, 1);
    put_u64(&mut buf, s1 + 16, 0x400000);
    put_u64(&mut buf, s1 + 24, text_off as u64);
    put_u64(&mut buf, s1 + 32, text_size as u64);

    let s2 = sh + 128;
    put_u32(&mut buf, s2 + 4, 2);
    put_u64(&mut buf, s2 + 24, symtab_off as u64);
    put_u64(&mut buf, s2 + 32, symtab_size as u64);
    put_u32(&mut buf, s2 + 40, 3);
    put_u64(&mut buf, s2 + 56, 24);

    let s3 = sh + 192;
    put_u32(&mut buf, s3 + 4, 3);
    put_u64(&mut buf, s3 + 24, strtab_off as u64);
    put_u64(&mut buf, s3 + 32, strtab.len() as u64);

    buf
}

#[test]
fn x64_elf_reports_nonzero_instruction_count() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("sample.elf");
    fs::write(&path, sample_x64_elf()).expect("write elf");
    let output = Command::new(env!("CARGO_BIN_EXE_revx-micro"))
        .arg("analyze")
        .arg(&path)
        .output()
        .expect("run micro");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("\"architecture\":\"x64\""), "{text}");
    assert!(text.contains("\"name\":\"main\""), "{text}");
    let insts_pos = text.find("\"insts\":").expect("insts field");
    let insts: usize = text[insts_pos + 8..]
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .expect("insts value")
        .parse()
        .expect("parse insts");
    assert!(insts > 0, "x64 instruction count must not be zero: {text}");
}

#[test]
fn missing_path_exits_with_usage_not_panic() {
    let output = Command::new(env!("CARGO_BIN_EXE_revx-micro"))
        .arg("analyze")
        .output()
        .expect("run micro");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("revx-micro analyze"));
}

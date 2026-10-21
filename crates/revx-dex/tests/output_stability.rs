use revx_dex::render::decompile_method;
use revx_dex::{CodeItem, DexFile};
use std::env;
use std::fs;
use std::process::Command;

fn dex() -> DexFile {
    let mut bytes = vec![0; 0x70];
    bytes[..8].copy_from_slice(b"dex\n039\0");
    DexFile::parse(bytes).unwrap()
}

fn const4(reg: u16, lit: u16) -> u16 {
    0x0012 | ((reg & 0xf) << 8) | ((lit & 0xf) << 12)
}

fn diamond_regs() -> CodeItem {
    let mut insns = vec![const4(0, 1), 0x0038, 9];
    for (reg, lit) in (0..6).map(|reg| (reg, reg + 2)) {
        insns.push(const4(reg, lit));
    }
    insns.push(0x0728);
    for reg in 0..6 {
        insns.push(const4(reg, reg));
    }
    insns.extend([0x0090, 0x0100, 0x000f]);
    CodeItem {
        registers_size: 6,
        ins_size: 0,
        outs_size: 0,
        tries_size: 0,
        debug_info_off: 0,
        insns,
        tries: vec![],
    }
}

fn pseudocode() -> String {
    decompile_method(&dex(), &diamond_regs(), 0).pseudocode
}

#[test]
fn dex_diamond_pseudocode_matches_across_processes() {
    if let Ok(path) = env::var("REVX_DRIFT_OUT") {
        fs::write(path, pseudocode()).unwrap();
        return;
    }
    let exe = env::current_exe().unwrap();
    let mut texts = Vec::new();
    for i in 0..4 {
        let path = env::temp_dir().join(format!("revx-dex-drift-{}-{i}.txt", std::process::id()));
        let output = Command::new(&exe)
            .args([
                "--exact",
                "dex_diamond_pseudocode_matches_across_processes",
                "--test-threads=1",
            ])
            .env("REVX_DRIFT_OUT", &path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let text = fs::read_to_string(&path).unwrap();
        let _ = fs::remove_file(&path);
        assert!(
            text.contains("return"),
            "diamond did not render a return:\n{text}"
        );
        texts.push(text);
    }
    assert!(
        texts[0].contains("v16 = v3;\n        v17 = v4;\n        v18 = v5;\n        v19 = v6;\n        v20 = v7;\n        v21 = v8;"),
        "join copies must follow ascending registers:\n{}",
        texts[0]
    );
    assert!(
        texts[0].contains("v22 = v16 + v17;"),
        "add must use the v0 phi then the v1 phi:\n{}",
        texts[0]
    );
    for (i, text) in texts.iter().enumerate().skip(1) {
        assert_eq!(
            texts[0].as_str(),
            text.as_str(),
            "DEX pseudocode drifted between process 0 and process {i}\n--- 0 ---\n{}\n--- {i} ---\n{text}",
            texts[0]
        );
    }
}

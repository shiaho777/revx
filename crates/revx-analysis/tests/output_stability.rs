use revx_analysis::ssa::{lift_arm64_to_ssa, render_ssa_pseudocode_named_layered};
use revx_core::{BasicBlock, Instruction, Reference, ReferenceKind};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::process::Command;
use std::sync::Arc;

fn inst(addr: u64, text: &str) -> Instruction {
    Instruction {
        address: addr,
        bytes: Arc::from("00000000"),
        text: Arc::from(text),
    }
}

fn block(address: u64, lines: &[(u64, &str)]) -> BasicBlock {
    BasicBlock {
        address,
        size: lines.len() as u64 * 4,
        instructions: lines.iter().map(|(addr, text)| inst(*addr, text)).collect(),
    }
}

fn pseudocode() -> String {
    let blocks = vec![
        block(
            0x1000,
            &[
                (0x1000, "mov x0, #0x1"),
                (0x1004, "mov x1, #0x2"),
                (0x1008, "mov x2, #0x3"),
                (0x100c, "mov x3, #0x4"),
                (0x1010, "b.eq $+0x14"),
            ],
        ),
        block(
            0x1100,
            &[
                (0x1100, "mov x0, #0x5"),
                (0x1104, "mov x1, #0x6"),
                (0x1108, "mov x2, #0x7"),
                (0x110c, "mov x3, #0x8"),
                (0x1110, "b $+0x10"),
            ],
        ),
        block(
            0x2000,
            &[
                (0x2000, "mov x0, #0x9"),
                (0x2004, "mov x1, #0xa"),
                (0x2008, "mov x2, #0xb"),
                (0x200c, "mov x3, #0xc"),
                (0x2010, "b $+0x10"),
            ],
        ),
        block(0x3000, &[(0x3000, "add x0, x0, x1"), (0x3004, "ret")]),
    ];
    let refs = vec![
        Reference {
            from: 0x1010,
            to: 0x2000,
            kind: ReferenceKind::BranchTrue,
        },
        Reference {
            from: 0x1010,
            to: 0x1100,
            kind: ReferenceKind::BranchFalse,
        },
        Reference {
            from: 0x1110,
            to: 0x3000,
            kind: ReferenceKind::Jump,
        },
        Reference {
            from: 0x2010,
            to: 0x3000,
            kind: ReferenceKind::Jump,
        },
    ];
    let func = lift_arm64_to_ssa(&blocks, &refs, &[]);
    render_ssa_pseudocode_named_layered(&func, "diamond", &[], &HashMap::new(), &HashMap::new())
}

#[test]
fn native_diamond_pseudocode_matches_across_processes() {
    if let Ok(path) = env::var("REVX_DRIFT_OUT") {
        fs::write(path, pseudocode()).unwrap();
        return;
    }
    let exe = env::current_exe().unwrap();
    let mut texts = Vec::new();
    for i in 0..4 {
        let path =
            env::temp_dir().join(format!("revx-native-drift-{}-{i}.txt", std::process::id()));
        let output = Command::new(&exe)
            .args([
                "--exact",
                "native_diamond_pseudocode_matches_across_processes",
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
            text.contains("return") || text.contains("add"),
            "diamond did not render:\n{text}"
        );
        texts.push(text);
    }
    for (i, text) in texts.iter().enumerate().skip(1) {
        assert_eq!(
            texts[0].as_str(),
            text.as_str(),
            "native pseudocode drifted between process 0 and process {i}\n--- 0 ---\n{}\n--- {i} ---\n{text}",
            texts[0]
        );
    }
}

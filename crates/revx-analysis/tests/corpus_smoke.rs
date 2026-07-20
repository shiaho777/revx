use revx_analysis::analyze;
use revx_core::AnalysisProfile;
use revx_loader::load_binary;
use std::path::{Path, PathBuf};

fn corpus_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(dir) = std::env::var("REVX_CORPUS_DIR") {
        let root = PathBuf::from(dir);
        if root.is_dir() {
            if let Ok(rd) = std::fs::read_dir(&root) {
                for entry in rd.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        out.push(path);
                    }
                }
            }
        } else if root.is_file() {
            out.push(root);
        }
    }
    // built-in optional local samples
    for candidate in [
        "/Users/shiaho/Downloads/AndMX/app/build/intermediates/cxx/Debug/5e11264s/obj/arm64-v8a/libandmxpty.so",
    ] {
        let p = PathBuf::from(candidate);
        if p.exists() {
            out.push(p);
        }
    }
    out.sort();
    out.dedup();
    out.into_iter().take(12).collect()
}

fn looks_like_binary(path: &Path) -> bool {
    let Ok(bytes) = std::fs::read(path) else {
        return false;
    };
    if bytes.len() < 4 {
        return false;
    }
    matches!(
        &bytes[0..4],
        [0x7f, b'E', b'L', b'F'] | [b'M', b'Z', _, _] | [0xcf, 0xfa, 0xed, 0xfe] | [0xce, 0xfa, 0xed, 0xfe] | [0xca, 0xfe, 0xba, 0xbe]
    )
}

#[test]
fn corpus_smoke_load_and_analyze() {
    let paths = corpus_paths()
        .into_iter()
        .filter(|p| looks_like_binary(p))
        .collect::<Vec<_>>();
    if paths.is_empty() {
        // no corpus available in this environment
        return;
    }
    let mut analyzed = 0usize;
    for path in paths {
        let Ok(image) = load_binary(&path) else {
            continue;
        };
        let fast = analyze(image.clone(), AnalysisProfile::Fast);
        assert!(
            fast.survey.summary.function_count > 0 || !image.symbols.is_empty() || image.entry.is_some(),
            "no analysis surface for {}",
            path.display()
        );
        let full = analyze(image, AnalysisProfile::Full);
        assert!(
            !full.functions.is_empty()
                || full.survey.summary.function_count > 0
                || !full.types.is_empty(),
            "full analysis empty for {}",
            path.display()
        );
        analyzed += 1;
    }
    assert!(analyzed > 0, "no corpus binary could be analyzed");
}

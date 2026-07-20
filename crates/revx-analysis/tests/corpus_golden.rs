use revx_analysis::{analyze, recompose_function_pseudocode, resolve_decompile_strategy};
use revx_core::{AnalysisProfile, DecompileStrategy};
use revx_loader::load_binary;
use std::collections::BTreeMap;
use std::path::PathBuf;

fn sample_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(dir) = std::env::var("REVX_CORPUS_DIR") {
        let root = PathBuf::from(dir);
        if root.is_dir() {
            if let Ok(rd) = std::fs::read_dir(root) {
                for e in rd.flatten() {
                    if e.path().is_file() {
                        out.push(e.path());
                    }
                }
            }
        }
    }
    let local = PathBuf::from(
        "/Users/shiaho/Downloads/AndMX/app/build/intermediates/cxx/Debug/5e11264s/obj/arm64-v8a/libandmxpty.so",
    );
    if local.exists() {
        out.push(local);
    }
    out.sort();
    out.dedup();
    out.into_iter().take(6).collect()
}

fn fingerprint_function(name: &str, address: u64, text: &str, region_count: usize) -> String {
    let mut sample = text.chars().take(240).collect::<String>();
    sample.retain(|c| !c.is_control() || c == '\n');
    format!("{name}@{address:x}|regions={region_count}|text={sample}")
}

#[test]
fn golden_strategy_fingerprints_are_stable() {
    let paths = sample_paths();
    if paths.is_empty() {
        return;
    }
    let mut snapshots: BTreeMap<String, String> = BTreeMap::new();
    for path in paths {
        let Ok(image) = load_binary(&path) else {
            continue;
        };
        let bundle = analyze(image, AnalysisProfile::Full);
        let Some(function) = bundle
            .functions
            .iter()
            .max_by_key(|f| f.blocks.iter().map(|b| b.instructions.len()).sum::<usize>())
        else {
            continue;
        };
        let insts = function
            .blocks
            .iter()
            .map(|b| b.instructions.len())
            .sum::<usize>();
        for strategy in [
            DecompileStrategy::Fast,
            DecompileStrategy::Full,
            DecompileStrategy::Hotblock,
        ] {
            let used = resolve_decompile_strategy(strategy, true, false, insts);
            let unit = recompose_function_pseudocode(function, bundle.survey.summary.architecture, used);
            let key = format!(
                "{}:{}:{:?}",
                path.file_name().and_then(|s| s.to_str()).unwrap_or("bin"),
                function.name,
                used
            );
            snapshots.insert(
                key,
                fingerprint_function(
                    &function.name,
                    function.address,
                    &unit.text,
                    unit.regions.len(),
                ),
            );
        }
        // second pass must match
        for strategy in [
            DecompileStrategy::Fast,
            DecompileStrategy::Full,
            DecompileStrategy::Hotblock,
        ] {
            let used = resolve_decompile_strategy(strategy, true, false, insts);
            let unit = recompose_function_pseudocode(function, bundle.survey.summary.architecture, used);
            let key = format!(
                "{}:{}:{:?}",
                path.file_name().and_then(|s| s.to_str()).unwrap_or("bin"),
                function.name,
                used
            );
            let again = fingerprint_function(
                &function.name,
                function.address,
                &unit.text,
                unit.regions.len(),
            );
            assert_eq!(
                snapshots.get(&key).map(String::as_str),
                Some(again.as_str()),
                "unstable golden for {key}"
            );
        }
    }
    assert!(!snapshots.is_empty(), "no golden fingerprints produced");
}

#[test]
fn strategy_auto_prefers_cache_when_present() {
    let used = resolve_decompile_strategy(DecompileStrategy::Auto, false, true, 40);
    assert_eq!(used, DecompileStrategy::Cached);
    let used = resolve_decompile_strategy(DecompileStrategy::Auto, true, true, 40);
    assert_ne!(used, DecompileStrategy::Cached);
    let used = resolve_decompile_strategy(DecompileStrategy::Auto, true, false, 10_000);
    assert_eq!(used, DecompileStrategy::Hotblock);
}


#[test]
fn fast_path_emits_block_addresses() {
    let paths = sample_paths();
    if paths.is_empty() {
        // synthetic-free environments still validate pure strategy resolve
        let used = resolve_decompile_strategy(DecompileStrategy::Fast, true, false, 20);
        assert_eq!(used, DecompileStrategy::Fast);
        return;
    }
    let path = &paths[0];
    let Ok(image) = load_binary(path) else {
        return;
    };
    let bundle = analyze(image, AnalysisProfile::Full);
    let Some(function) = bundle.functions.iter().find(|f| !f.blocks.is_empty()) else {
        return;
    };
    let unit = recompose_function_pseudocode(
        function,
        bundle.survey.summary.architecture,
        DecompileStrategy::Fast,
    );
    let tagged = unit
        .text
        .lines()
        .filter(|line| line.contains("0x") || line.contains("// bb @"))
        .count();
    assert!(
        tagged >= 1,
        "expected address tags in fast pseudocode, got:\n{}",
        unit.text.chars().take(400).collect::<String>()
    );
}

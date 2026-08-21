use criterion::{Criterion, black_box, criterion_group, criterion_main};
use revx_analysis::analyze;
use revx_core::AnalysisProfile;
use revx_loader::load_binary;
use revx_testkit::{elf_args_call_cases, write_temp};

fn bench_analyze(c: &mut Criterion) {
    let mut group = c.benchmark_group("analyze");
    for case in elf_args_call_cases() {
        let path = write_temp(&case);
        for profile in [AnalysisProfile::Fast, AnalysisProfile::Full] {
            let id = format!("{}/{:?}", case.id, profile).to_lowercase();
            group.bench_with_input(id.as_str(), &path, |b, path| {
                b.iter(|| {
                    let image = load_binary(black_box(path)).expect("load fixture");
                    analyze(image, profile)
                })
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench_analyze);
criterion_main!(benches);

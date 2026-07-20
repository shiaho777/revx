
use object::write::{Object as WriteObject, StandardSection, Symbol, SymbolKind, SymbolScope, SymbolSection};
use object::{Architecture as ObjArch, BinaryFormat as ObjFmt, Endianness};
use revx_loader::load_binary;
use revx_analysis::analyze;
use revx_core::AnalysisProfile;
use std::fs;

fn main() {
    let code = vec![
        0x89, 0xff, 0x85, 0xff, 0x74, 0x03, 0x31, 0xc0, 0xc3,
        0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3,
    ];
    let mut obj = WriteObject::new(ObjFmt::Elf, ObjArch::X86_64, Endianness::Little);
    let section = obj.section_id(StandardSection::Text);
    let offset = obj.append_section_data(section, &code, 16);
    obj.add_symbol(Symbol {
        name: b"main".to_vec(),
        value: offset,
        size: code.len() as u64,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(section),
        flags: object::SymbolFlags::None,
    });
    let bytes = obj.write().unwrap();
    let path = std::env::temp_dir().join("revx-debug-elf.bin");
    fs::write(&path, &bytes).unwrap();
    let image = load_binary(&path).unwrap();
    println!("format={:?} arch={:?}", image.format, image.architecture);
    println!("sections={:?}", image.sections.iter().map(|s| (&s.name, s.address, s.size, &s.kind)).collect::<Vec<_>>());
    println!("segments={:?}", image.segments.iter().map(|s| (&s.name, s.address, s.size, &s.permissions)).collect::<Vec<_>>());
    println!("symbols={:?}", image.symbols.iter().map(|s| (&s.name, s.address, &s.kind)).collect::<Vec<_>>());
    println!("entry={:?}", image.entry);
    let bundle = analyze(image, AnalysisProfile::Fast);
    println!("funcs={}", bundle.survey.summary.function_count);
    for f in bundle.functions.iter().take(5) {
        println!("  {} @ {:#x} size={}", f.name, f.address, f.size);
    }
}

use revx_loader::load_binary;
use std::io::Write;
use std::path::PathBuf;

#[test]
fn loads_known_fixture() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("ida-pro-mcp-main")
        .join("tests")
        .join("typed_fixture.elf");
    if !root.exists() {
        return;
    }
    let image = load_binary(&root).unwrap();
    assert!(image.size > 0);
    assert!(!matches!(image.format, revx_core::BinaryFormat::Unknown));
}

#[test]
fn libtersafe_arm64_plt_import_addresses_match_real_stubs() {
    let root = PathBuf::from("/Users/shiaho/Desktop/ida-mini-mcp/libtersafe.so");
    if !root.exists() {
        return;
    }

    let image = load_binary(&root).unwrap();
    let find_addr = |name: &str| {
        image
            .imports
            .iter()
            .find(|import| import.name == name)
            .and_then(|import| import.address)
    };

    assert_eq!(find_addr("free"), Some(0x50e180));
    assert_eq!(find_addr("malloc"), Some(0x50e190));
    assert_eq!(find_addr("calloc"), Some(0x50e1a0));
}

#[test]
fn identifies_directory_as_universal_object_graph() {
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("sample.txt");
    std::fs::write(&nested, "hello universal analysis").unwrap();

    let graph = revx_loader::identify_object_graph(dir.path(), 1, 16).unwrap();

    assert_eq!(graph.objects.len(), 2);
    assert_eq!(graph.edges.len(), 1);
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.kind, revx_core::ObjectKind::Directory);
    let child = graph
        .objects
        .iter()
        .find(|object| object.path.as_deref() == Some(nested.to_str().unwrap()))
        .unwrap();
    assert_eq!(child.kind, revx_core::ObjectKind::Text);
    assert!(child.hash_blake3.is_some());
    assert!(child.entropy.is_some());
    assert!(
        child
            .analyses
            .iter()
            .any(|analysis| analysis.analyzer == "text_summary")
    );
}

#[test]
fn expands_zip_container_entries_into_object_graph() {
    let dir = tempfile::tempdir().unwrap();
    let archive_path = dir.path().join("sample.jar");
    {
        let file = std::fs::File::create(&archive_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("classes.dex", options).unwrap();
        zip.write_all(b"dex\n035\0test").unwrap();
        zip.start_file("META-INF/MANIFEST.MF", options).unwrap();
        zip.write_all(b"Manifest-Version: 1.0\n").unwrap();
        zip.finish().unwrap();
    }

    let graph = revx_loader::identify_object_graph(&archive_path, 1, 16).unwrap();
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.kind, revx_core::ObjectKind::Package);
    assert!(
        root.analyses
            .iter()
            .any(|analysis| analysis.analyzer == "zip_container")
    );
    assert_eq!(graph.edges.len(), 2);
    assert!(graph.objects.iter().any(|object| {
        object.display_name == "classes.dex"
            && object.kind == revx_core::ObjectKind::Binary
            && object
                .analyses
                .iter()
                .any(|analysis| analysis.analyzer == "dex_header")
    }));
    assert!(graph.objects.iter().any(|object| {
        object.display_name == "META-INF/MANIFEST.MF"
            && object.kind == revx_core::ObjectKind::Text
            && object
                .analyses
                .iter()
                .any(|analysis| analysis.analyzer == "text_summary")
    }));
}

#[test]
fn identifies_sqlite_database_with_header_analysis() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("sample.sqlite");
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT NOT NULL);
             CREATE INDEX idx_users_name ON users(name);",
        )
        .unwrap();
    }

    let graph = revx_loader::identify_object_graph(&db_path, 1, 16).unwrap();
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.kind, revx_core::ObjectKind::Database);
    assert_eq!(root.format.as_deref(), Some("sqlite"));
    assert!(
        root.analyses
            .iter()
            .any(|analysis| analysis.analyzer == "sqlite_header"
                && analysis.status == revx_core::ObjectAnalysisStatus::Completed)
    );
}

#[test]
fn identifies_wasm_module_with_header_analysis() {
    let dir = tempfile::tempdir().unwrap();
    let wasm_path = dir.path().join("sample.wasm");
    std::fs::write(&wasm_path, sample_wasm_module()).unwrap();

    let graph = revx_loader::identify_object_graph(&wasm_path, 1, 16).unwrap();
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.kind, revx_core::ObjectKind::Binary);
    assert_eq!(root.format.as_deref(), Some("wasm"));
    assert!(
        root.analyses
            .iter()
            .any(|analysis| analysis.analyzer == "wasm_header"
                && analysis.status == revx_core::ObjectAnalysisStatus::Completed)
    );
}

#[test]
fn identifies_windows_shell_links_with_header_analysis() {
    let dir = tempfile::tempdir().unwrap();
    let lnk_path = dir.path().join("launch.lnk");
    std::fs::write(&lnk_path, sample_shell_link()).unwrap();

    let graph = revx_loader::identify_object_graph(&lnk_path, 1, 16).unwrap();
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.kind, revx_core::ObjectKind::File);
    assert_eq!(root.format.as_deref(), Some("lnk"));
    assert_eq!(
        root.media_type.as_deref(),
        Some("application/x-ms-shortcut")
    );
    assert!(root.analyses.iter().any(|analysis| {
        analysis.analyzer == "lnk_header"
            && analysis.status == revx_core::ObjectAnalysisStatus::Completed
            && analysis.details["link_flags"].as_u64().unwrap() & 0x80 != 0
    }));
}

#[test]
fn identifies_safetensors_models_with_header_analysis() {
    let dir = tempfile::tempdir().unwrap();
    let model_path = dir.path().join("adapter.safetensors");
    std::fs::write(&model_path, sample_safetensors_model()).unwrap();

    let graph = revx_loader::identify_object_graph(&model_path, 1, 16).unwrap();
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.kind, revx_core::ObjectKind::Model);
    assert_eq!(root.format.as_deref(), Some("safetensors"));
    assert_eq!(
        root.media_type.as_deref(),
        Some("application/x-safetensors")
    );
    assert!(root.analyses.iter().any(|analysis| {
        analysis.analyzer == "safetensors_header"
            && analysis.status == revx_core::ObjectAnalysisStatus::Completed
            && analysis.details["tensor_count"] == serde_json::json!(3)
    }));
}

#[test]
fn identifies_safetensors_index_json_as_model() {
    let dir = tempfile::tempdir().unwrap();
    let index_path = dir.path().join("model.safetensors.index.json");
    std::fs::write(&index_path, sample_safetensors_index()).unwrap();

    let graph = revx_loader::identify_object_graph(&index_path, 1, 16).unwrap();
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.kind, revx_core::ObjectKind::Model);
    assert_eq!(root.format.as_deref(), Some("safetensors_index"));
    assert_eq!(root.media_type.as_deref(), Some("application/json"));
    assert!(root.analyses.iter().any(|analysis| {
        analysis.analyzer == "json_structure"
            && analysis.status == revx_core::ObjectAnalysisStatus::Completed
            && analysis.details["keys"]
                .as_array()
                .unwrap()
                .iter()
                .any(|key| key.as_str() == Some("weight_map"))
    }));
}

#[test]
fn identifies_gguf_models_with_header_analysis() {
    let dir = tempfile::tempdir().unwrap();
    let model_path = dir.path().join("Tiny-1B-v1.0-Q4_0.gguf");
    std::fs::write(&model_path, sample_gguf_model()).unwrap();

    let graph = revx_loader::identify_object_graph(&model_path, 1, 16).unwrap();
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.kind, revx_core::ObjectKind::Model);
    assert_eq!(root.format.as_deref(), Some("gguf"));
    assert_eq!(root.media_type.as_deref(), Some("application/x-gguf"));
    assert!(root.analyses.iter().any(|analysis| {
        analysis.analyzer == "gguf_header"
            && analysis.status == revx_core::ObjectAnalysisStatus::Completed
            && analysis.details["version"] == serde_json::json!(3)
            && analysis.details["tensor_count"] == serde_json::json!(2)
            && analysis.details["metadata_kv_count"] == serde_json::json!(4)
    }));
}

#[test]
fn identifies_pytorch_zip_models_with_header_analysis() {
    let dir = tempfile::tempdir().unwrap();
    let model_path = dir.path().join("checkpoint.pt");
    std::fs::write(&model_path, sample_pytorch_zip_model()).unwrap();

    let graph = revx_loader::identify_object_graph(&model_path, 1, 16).unwrap();
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.kind, revx_core::ObjectKind::Model);
    assert_eq!(root.format.as_deref(), Some("pytorch"));
    assert_eq!(root.media_type.as_deref(), Some("application/x-pytorch"));
    assert!(root.analyses.iter().any(|analysis| {
        analysis.analyzer == "pytorch_header"
            && analysis.status == revx_core::ObjectAnalysisStatus::Completed
            && analysis.details["container"] == serde_json::json!("zip")
            && analysis.details["pickle_present"] == serde_json::json!(true)
    }));
}

#[test]
fn identifies_pdf_document_with_header_analysis() {
    let dir = tempfile::tempdir().unwrap();
    let pdf_path = dir.path().join("sample.pdf");
    std::fs::write(&pdf_path, sample_pdf_document()).unwrap();

    let graph = revx_loader::identify_object_graph(&pdf_path, 1, 16).unwrap();
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.kind, revx_core::ObjectKind::Document);
    assert_eq!(root.format.as_deref(), Some("pdf"));
    assert!(
        root.analyses
            .iter()
            .any(|analysis| analysis.analyzer == "pdf_header"
                && analysis.status == revx_core::ObjectAnalysisStatus::Completed)
    );
}

#[test]
fn expands_ole_compound_streams_into_object_graph() {
    let dir = tempfile::tempdir().unwrap();
    let ole_path = dir.path().join("legacy.doc");
    std::fs::write(&ole_path, sample_ole_compound_file()).unwrap();

    let graph = revx_loader::identify_object_graph(&ole_path, 2, 16).unwrap();
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.kind, revx_core::ObjectKind::Document);
    assert_eq!(root.format.as_deref(), Some("doc"));
    assert!(root.flags.iter().any(|flag| flag == "container_candidate"));
    assert!(root.analyses.iter().any(|analysis| {
        analysis.analyzer == "ole_header"
            && analysis.status == revx_core::ObjectAnalysisStatus::Completed
    }));
    assert!(root.analyses.iter().any(|analysis| {
        analysis.analyzer == "ole_container"
            && analysis.status == revx_core::ObjectAnalysisStatus::Completed
            && analysis.details["stream_count"] == serde_json::json!(2)
    }));

    let vba_stream = graph
        .objects
        .iter()
        .find(|object| object.display_name == "VBA/dir")
        .expect("VBA stream object");
    assert_eq!(
        vba_stream.metadata["container_format"],
        serde_json::json!("ole")
    );
    assert_eq!(
        vba_stream.metadata["ole_stream_path"],
        serde_json::json!("VBA/dir")
    );
    assert!(graph.edges.iter().any(|edge| {
        edge.from == root.id
            && edge.to == vba_stream.id
            && edge.kind == revx_core::ObjectEdgeKind::Contains
            && edge.metadata["container_format"] == serde_json::json!("ole")
    }));
}

#[test]
fn identifies_png_image_with_header_analysis() {
    let dir = tempfile::tempdir().unwrap();
    let png_path = dir.path().join("sample.png");
    std::fs::write(&png_path, sample_png_image()).unwrap();

    let graph = revx_loader::identify_object_graph(&png_path, 1, 16).unwrap();
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.kind, revx_core::ObjectKind::Image);
    assert_eq!(root.format.as_deref(), Some("png"));
    let png = root
        .analyses
        .iter()
        .find(|analysis| analysis.analyzer == "png_header")
        .expect("png header analysis");
    assert_eq!(png.status, revx_core::ObjectAnalysisStatus::Completed);
    assert_eq!(png.details["ihdr"]["width"], serde_json::json!(2));
    assert_eq!(png.details["ihdr"]["height"], serde_json::json!(3));
}

#[test]
fn identifies_jpeg_image_with_header_analysis() {
    let dir = tempfile::tempdir().unwrap();
    let jpeg_path = dir.path().join("sample.jpg");
    std::fs::write(&jpeg_path, sample_jpeg_image()).unwrap();

    let graph = revx_loader::identify_object_graph(&jpeg_path, 1, 16).unwrap();
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.kind, revx_core::ObjectKind::Image);
    assert_eq!(root.format.as_deref(), Some("jpeg"));
    let jpeg = root
        .analyses
        .iter()
        .find(|analysis| analysis.analyzer == "jpeg_header")
        .expect("jpeg header analysis");
    assert_eq!(jpeg.status, revx_core::ObjectAnalysisStatus::Completed);
    assert_eq!(jpeg.details["frame"]["width"], serde_json::json!(4));
    assert_eq!(jpeg.details["frame"]["height"], serde_json::json!(5));
}

#[test]
fn identifies_gif_image_with_header_analysis() {
    let dir = tempfile::tempdir().unwrap();
    let gif_path = dir.path().join("sample.gif");
    std::fs::write(&gif_path, sample_gif_image()).unwrap();

    let graph = revx_loader::identify_object_graph(&gif_path, 1, 16).unwrap();
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.kind, revx_core::ObjectKind::Image);
    assert_eq!(root.format.as_deref(), Some("gif"));
    let gif = root
        .analyses
        .iter()
        .find(|analysis| analysis.analyzer == "gif_header")
        .expect("gif header analysis");
    assert_eq!(gif.status, revx_core::ObjectAnalysisStatus::Completed);
    assert_eq!(gif.details["header"]["width"], serde_json::json!(4));
    assert_eq!(gif.details["header"]["height"], serde_json::json!(5));
}

#[test]
fn expands_ico_image_entries_into_object_graph() {
    let dir = tempfile::tempdir().unwrap();
    let ico_path = dir.path().join("sample.ico");
    let png = sample_png_image();
    std::fs::write(&ico_path, sample_ico_with_png_icon(&png)).unwrap();

    let graph = revx_loader::identify_object_graph(&ico_path, 1, 16).unwrap();
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.kind, revx_core::ObjectKind::Image);
    assert_eq!(root.format.as_deref(), Some("ico"));
    assert!(root.flags.iter().any(|flag| flag == "container_candidate"));
    assert!(
        root.analyses
            .iter()
            .any(|analysis| analysis.analyzer == "ico_header"
                && analysis.status == revx_core::ObjectAnalysisStatus::Completed)
    );
    assert!(
        root.analyses
            .iter()
            .any(|analysis| analysis.analyzer == "ico_container"
                && analysis.status == revx_core::ObjectAnalysisStatus::Completed)
    );
    assert_eq!(graph.edges.len(), 1);
    let child = graph
        .objects
        .iter()
        .find(|object| object.display_name == "icon_0_16x16_32bpp.png")
        .expect("ico png child");
    assert_eq!(child.kind, revx_core::ObjectKind::Image);
    assert_eq!(child.format.as_deref(), Some("png"));
    assert_eq!(child.metadata["container_format"], serde_json::json!("ico"));
    assert_eq!(child.metadata["ico_entry"], serde_json::json!(0));
    assert!(
        child
            .analyses
            .iter()
            .any(|analysis| analysis.analyzer == "png_header")
    );
}

#[test]
fn identifies_bmp_image_with_header_analysis() {
    let dir = tempfile::tempdir().unwrap();
    let bmp_path = dir.path().join("sample.bmp");
    std::fs::write(&bmp_path, sample_bmp_file()).unwrap();

    let graph = revx_loader::identify_object_graph(&bmp_path, 1, 16).unwrap();
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.kind, revx_core::ObjectKind::Image);
    assert_eq!(root.format.as_deref(), Some("bmp"));
    let bmp = root
        .analyses
        .iter()
        .find(|analysis| analysis.analyzer == "bmp_header")
        .expect("bmp header analysis");
    assert_eq!(bmp.status, revx_core::ObjectAnalysisStatus::Completed);
    assert_eq!(bmp.details["header"]["width"], serde_json::json!(2));
    assert_eq!(bmp.details["header"]["height"], serde_json::json!(2));
    assert_eq!(bmp.details["header"]["bit_count"], serde_json::json!(32));
}

#[test]
fn expands_ico_dib_entries_into_object_graph() {
    let dir = tempfile::tempdir().unwrap();
    let ico_path = dir.path().join("bitmap.ico");
    let dib = sample_ico_dib_payload();
    std::fs::write(&ico_path, sample_ico_with_dib_icon(&dib)).unwrap();

    let graph = revx_loader::identify_object_graph(&ico_path, 1, 16).unwrap();
    let child = graph
        .objects
        .iter()
        .find(|object| object.display_name == "icon_0_16x16_32bpp.dib")
        .expect("ico dib child");
    assert_eq!(child.kind, revx_core::ObjectKind::Image);
    assert_eq!(child.format.as_deref(), Some("dib"));
    assert_eq!(child.metadata["container_format"], serde_json::json!("ico"));
    assert!(
        child
            .analyses
            .iter()
            .any(|analysis| analysis.analyzer == "bmp_header"
                && analysis.status == revx_core::ObjectAnalysisStatus::Completed)
    );
}

#[test]
fn expands_riff_webp_chunks_into_object_graph() {
    let dir = tempfile::tempdir().unwrap();
    let webp_path = dir.path().join("sample.webp");
    std::fs::write(&webp_path, sample_webp_riff()).unwrap();

    let graph = revx_loader::identify_object_graph(&webp_path, 1, 16).unwrap();
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.kind, revx_core::ObjectKind::Image);
    assert_eq!(root.format.as_deref(), Some("webp"));
    assert!(root.flags.iter().any(|flag| flag == "container_candidate"));
    let header = root
        .analyses
        .iter()
        .find(|analysis| analysis.analyzer == "riff_header")
        .expect("riff header analysis");
    assert_eq!(header.status, revx_core::ObjectAnalysisStatus::Completed);
    assert_eq!(header.details["form_type"], serde_json::json!("WEBP"));
    assert_eq!(header.details["chunk_count"], serde_json::json!(2));
    assert!(
        root.analyses
            .iter()
            .any(|analysis| analysis.analyzer == "riff_container"
                && analysis.status == revx_core::ObjectAnalysisStatus::Completed)
    );

    let vp8x = graph
        .objects
        .iter()
        .find(|object| object.display_name == "riff_000_WEBP_VP8X.bin")
        .expect("vp8x child");
    assert_eq!(vp8x.metadata["container_format"], serde_json::json!("riff"));
    assert_eq!(vp8x.metadata["riff_form_type"], serde_json::json!("WEBP"));
    assert_eq!(vp8x.metadata["riff_chunk_id"], serde_json::json!("VP8X"));
    assert_eq!(vp8x.metadata["riff_chunk_size"], serde_json::json!(10));
    let iccp = graph
        .objects
        .iter()
        .find(|object| object.display_name == "riff_001_WEBP_ICCP.icc")
        .expect("iccp child");
    assert_eq!(iccp.metadata["riff_chunk_id"], serde_json::json!("ICCP"));
    assert_eq!(graph.edges.len(), 2);
}

#[test]
fn identifies_pcap_capture_with_header_analysis() {
    let dir = tempfile::tempdir().unwrap();
    let pcap_path = dir.path().join("sample.pcap");
    std::fs::write(&pcap_path, sample_pcap_capture()).unwrap();

    let graph = revx_loader::identify_object_graph(&pcap_path, 1, 16).unwrap();
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.kind, revx_core::ObjectKind::NetworkCapture);
    assert_eq!(root.format.as_deref(), Some("pcap"));
    let header = root
        .analyses
        .iter()
        .find(|analysis| analysis.analyzer == "pcap_header")
        .expect("pcap header analysis");
    assert_eq!(header.status, revx_core::ObjectAnalysisStatus::Completed);
    assert_eq!(header.details["container"], serde_json::json!("pcap"));
    assert_eq!(header.details["snaplen"], serde_json::json!(65_535));
    assert_eq!(
        header.details["network_name"],
        serde_json::json!("ETHERNET")
    );
}

#[test]
fn identifies_pcapng_capture_with_header_analysis() {
    let dir = tempfile::tempdir().unwrap();
    let pcapng_path = dir.path().join("sample.pcapng");
    std::fs::write(&pcapng_path, sample_pcapng_capture()).unwrap();

    let graph = revx_loader::identify_object_graph(&pcapng_path, 1, 16).unwrap();
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.kind, revx_core::ObjectKind::NetworkCapture);
    assert_eq!(root.format.as_deref(), Some("pcapng"));
    let header = root
        .analyses
        .iter()
        .find(|analysis| analysis.analyzer == "pcap_header")
        .expect("pcapng header analysis");
    assert_eq!(header.status, revx_core::ObjectAnalysisStatus::Completed);
    assert_eq!(header.details["container"], serde_json::json!("pcapng"));
    assert_eq!(header.details["version"], serde_json::json!("1.0"));
}

#[test]
fn expands_tar_container_entries_into_object_graph() {
    let dir = tempfile::tempdir().unwrap();
    let archive_path = dir.path().join("sample.tar");
    {
        let file = std::fs::File::create(&archive_path).unwrap();
        let mut tar = tar::Builder::new(file);
        let config = br#"{"agent":"revx","rules":[1,2,3]}"#;
        let mut config_header = tar::Header::new_gnu();
        config_header.set_size(config.len() as u64);
        config_header.set_cksum();
        tar.append_data(&mut config_header, "config.json", &config[..])
            .unwrap();
        let payload = b"hello from tar";
        let mut payload_header = tar::Header::new_gnu();
        payload_header.set_size(payload.len() as u64);
        payload_header.set_cksum();
        tar.append_data(&mut payload_header, "bin/payload.txt", &payload[..])
            .unwrap();
        tar.finish().unwrap();
    }

    let graph = revx_loader::identify_object_graph(&archive_path, 1, 16).unwrap();
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.kind, revx_core::ObjectKind::Archive);
    assert_eq!(root.format.as_deref(), Some("tar"));
    assert!(
        root.analyses
            .iter()
            .any(|analysis| analysis.analyzer == "tar_container")
    );
    assert_eq!(graph.edges.len(), 2);
    assert!(graph.objects.iter().any(|object| {
        object.display_name == "config.json"
            && object.kind == revx_core::ObjectKind::Text
            && object.format.as_deref() == Some("json")
            && object.metadata["container_format"] == serde_json::json!("tar")
            && object.metadata["tar_entry"] == serde_json::json!("config.json")
            && object
                .analyses
                .iter()
                .any(|analysis| analysis.analyzer == "json_structure")
    }));
    assert!(graph.objects.iter().any(|object| {
        object.display_name == "bin/payload.txt"
            && object.kind == revx_core::ObjectKind::Text
            && object
                .analyses
                .iter()
                .any(|analysis| analysis.analyzer == "text_summary")
    }));
}

#[test]
fn expands_gzip_tar_container_entries_into_object_graph() {
    let dir = tempfile::tempdir().unwrap();
    let archive_path = dir.path().join("sample.tgz");
    {
        let file = std::fs::File::create(&archive_path).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut tar = tar::Builder::new(encoder);
        let config = br#"{"agent":"revx","compressed":true}"#;
        let mut config_header = tar::Header::new_gnu();
        config_header.set_size(config.len() as u64);
        config_header.set_cksum();
        tar.append_data(&mut config_header, "config.json", &config[..])
            .unwrap();
        tar.finish().unwrap();
        tar.into_inner().unwrap().finish().unwrap();
    }

    let graph = revx_loader::identify_object_graph(&archive_path, 1, 16).unwrap();
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.kind, revx_core::ObjectKind::Archive);
    assert_eq!(root.format.as_deref(), Some("tar.gz"));
    assert!(
        root.analyses
            .iter()
            .any(|analysis| analysis.analyzer == "tar_container")
    );
    assert!(graph.objects.iter().any(|object| {
        object.display_name == "config.json"
            && object.kind == revx_core::ObjectKind::Text
            && object.metadata["container_format"] == serde_json::json!("tar.gz")
            && object.metadata["tar_entry"] == serde_json::json!("config.json")
            && object
                .analyses
                .iter()
                .any(|analysis| analysis.analyzer == "json_structure")
    }));
}

#[test]
fn expands_bzip2_tar_container_entries_into_object_graph() {
    let dir = tempfile::tempdir().unwrap();
    let archive_path = dir.path().join("sample.tbz2");
    {
        let file = std::fs::File::create(&archive_path).unwrap();
        let encoder = bzip2::write::BzEncoder::new(file, bzip2::Compression::default());
        let mut tar = tar::Builder::new(encoder);
        let config = br#"{"agent":"revx","compressed":"bzip2"}"#;
        let mut config_header = tar::Header::new_gnu();
        config_header.set_size(config.len() as u64);
        config_header.set_cksum();
        tar.append_data(&mut config_header, "config.json", &config[..])
            .unwrap();
        tar.finish().unwrap();
        tar.into_inner().unwrap().finish().unwrap();
    }

    let graph = revx_loader::identify_object_graph(&archive_path, 1, 16).unwrap();
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.kind, revx_core::ObjectKind::Archive);
    assert_eq!(root.format.as_deref(), Some("tar.bz2"));
    assert!(
        root.analyses
            .iter()
            .any(|analysis| analysis.analyzer == "tar_container")
    );
    assert!(graph.objects.iter().any(|object| {
        object.display_name == "config.json"
            && object.kind == revx_core::ObjectKind::Text
            && object.metadata["container_format"] == serde_json::json!("tar.bz2")
            && object.metadata["tar_entry"] == serde_json::json!("config.json")
            && object
                .analyses
                .iter()
                .any(|analysis| analysis.analyzer == "json_structure")
    }));
}

#[test]
fn expands_xz_tar_container_entries_into_object_graph() {
    let dir = tempfile::tempdir().unwrap();
    let archive_path = dir.path().join("sample.txz");
    {
        let file = std::fs::File::create(&archive_path).unwrap();
        let encoder = xz2::write::XzEncoder::new(file, 6);
        let mut tar = tar::Builder::new(encoder);
        let config = br#"{"agent":"revx","compressed":"xz"}"#;
        let mut config_header = tar::Header::new_gnu();
        config_header.set_size(config.len() as u64);
        config_header.set_cksum();
        tar.append_data(&mut config_header, "config.json", &config[..])
            .unwrap();
        tar.finish().unwrap();
        tar.into_inner().unwrap().finish().unwrap();
    }

    let graph = revx_loader::identify_object_graph(&archive_path, 1, 16).unwrap();
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.kind, revx_core::ObjectKind::Archive);
    assert_eq!(root.format.as_deref(), Some("tar.xz"));
    assert!(
        root.analyses
            .iter()
            .any(|analysis| analysis.analyzer == "tar_container")
    );
    assert!(graph.objects.iter().any(|object| {
        object.display_name == "config.json"
            && object.kind == revx_core::ObjectKind::Text
            && object.metadata["container_format"] == serde_json::json!("tar.xz")
            && object.metadata["tar_entry"] == serde_json::json!("config.json")
            && object
                .analyses
                .iter()
                .any(|analysis| analysis.analyzer == "json_structure")
    }));
}

#[test]
fn expands_zstd_tar_container_entries_into_object_graph() {
    let dir = tempfile::tempdir().unwrap();
    let archive_path = dir.path().join("sample.tzst");
    {
        let mut tar_bytes = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut tar_bytes);
            let config = br#"{"agent":"revx","compressed":"zstd"}"#;
            let mut config_header = tar::Header::new_gnu();
            config_header.set_size(config.len() as u64);
            config_header.set_cksum();
            tar.append_data(&mut config_header, "config.json", &config[..])
                .unwrap();
            tar.finish().unwrap();
        }
        let compressed = ruzstd::encoding::compress_to_vec(
            tar_bytes.as_slice(),
            ruzstd::encoding::CompressionLevel::Fastest,
        );
        std::fs::write(&archive_path, compressed).unwrap();
    }

    let graph = revx_loader::identify_object_graph(&archive_path, 1, 16).unwrap();
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.kind, revx_core::ObjectKind::Archive);
    assert_eq!(root.format.as_deref(), Some("tar.zst"));
    assert!(
        root.analyses
            .iter()
            .any(|analysis| analysis.analyzer == "tar_container")
    );
    assert!(graph.objects.iter().any(|object| {
        object.display_name == "config.json"
            && object.kind == revx_core::ObjectKind::Text
            && object.metadata["container_format"] == serde_json::json!("tar.zst")
            && object.metadata["tar_entry"] == serde_json::json!("config.json")
            && object
                .analyses
                .iter()
                .any(|analysis| analysis.analyzer == "json_structure")
    }));
}

#[test]
fn expands_gzip_payload_into_object_graph() {
    let dir = tempfile::tempdir().unwrap();
    let archive_path = dir.path().join("config.json.gz");
    {
        let file = std::fs::File::create(&archive_path).unwrap();
        let mut encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        encoder
            .write_all(br#"{"agent":"revx","gzip_payload":true}"#)
            .unwrap();
        encoder.finish().unwrap();
    }

    let graph = revx_loader::identify_object_graph(&archive_path, 1, 16).unwrap();
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.kind, revx_core::ObjectKind::Archive);
    assert_eq!(root.format.as_deref(), Some("gzip"));
    assert!(
        root.analyses
            .iter()
            .any(|analysis| analysis.analyzer == "gzip_container")
    );
    assert_eq!(graph.edges.len(), 1);
    assert!(graph.objects.iter().any(|object| {
        object.display_name == "config.json"
            && object.kind == revx_core::ObjectKind::Text
            && object.format.as_deref() == Some("json")
            && object.metadata["container_format"] == serde_json::json!("gzip")
            && object.metadata["gzip_entry"] == serde_json::json!("config.json")
            && object
                .analyses
                .iter()
                .any(|analysis| analysis.analyzer == "json_structure")
    }));
}

#[test]
fn expands_zstd_payload_into_object_graph() {
    let dir = tempfile::tempdir().unwrap();
    let archive_path = dir.path().join("config.json.zst");
    {
        let compressed = ruzstd::encoding::compress_to_vec(
            &br#"{"agent":"revx","zstd_payload":true}"#[..],
            ruzstd::encoding::CompressionLevel::Fastest,
        );
        std::fs::write(&archive_path, compressed).unwrap();
    }

    let graph = revx_loader::identify_object_graph(&archive_path, 1, 16).unwrap();
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.kind, revx_core::ObjectKind::Archive);
    assert_eq!(root.format.as_deref(), Some("zstd"));
    assert!(
        root.analyses
            .iter()
            .any(|analysis| analysis.analyzer == "zstd_container")
    );
    assert_eq!(graph.edges.len(), 1);
    assert!(graph.objects.iter().any(|object| {
        object.display_name == "config.json"
            && object.kind == revx_core::ObjectKind::Text
            && object.format.as_deref() == Some("json")
            && object.metadata["container_format"] == serde_json::json!("zstd")
            && object.metadata["zstd_entry"] == serde_json::json!("config.json")
            && object
                .analyses
                .iter()
                .any(|analysis| analysis.analyzer == "json_structure")
    }));
}

#[test]
fn expands_xz_payload_into_object_graph() {
    let dir = tempfile::tempdir().unwrap();
    let archive_path = dir.path().join("config.json.xz");
    {
        let file = std::fs::File::create(&archive_path).unwrap();
        let mut encoder = xz2::write::XzEncoder::new(file, 6);
        encoder
            .write_all(br#"{"agent":"revx","xz_payload":true}"#)
            .unwrap();
        encoder.finish().unwrap();
    }

    let graph = revx_loader::identify_object_graph(&archive_path, 1, 16).unwrap();
    let root = graph
        .objects
        .iter()
        .find(|object| object.id == graph.root_id)
        .unwrap();
    assert_eq!(root.kind, revx_core::ObjectKind::Archive);
    assert_eq!(root.format.as_deref(), Some("xz"));
    assert!(
        root.analyses
            .iter()
            .any(|analysis| analysis.analyzer == "xz_container")
    );
    assert_eq!(graph.edges.len(), 1);
    assert!(graph.objects.iter().any(|object| {
        object.display_name == "config.json"
            && object.kind == revx_core::ObjectKind::Text
            && object.format.as_deref() == Some("json")
            && object.metadata["container_format"] == serde_json::json!("xz")
            && object.metadata["xz_entry"] == serde_json::json!("config.json")
            && object
                .analyses
                .iter()
                .any(|analysis| analysis.analyzer == "json_structure")
    }));
}

#[test]
fn identifies_java_class_entries_without_confusing_macho_fat_magic() {
    let dir = tempfile::tempdir().unwrap();
    let archive_path = dir.path().join("plugin.jar");
    {
        let file = std::fs::File::create(&archive_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("com/example/Main.class", options).unwrap();
        zip.write_all(&[0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x3d])
            .unwrap();
        zip.finish().unwrap();
    }

    let graph = revx_loader::identify_object_graph(&archive_path, 1, 16).unwrap();
    let class = graph
        .objects
        .iter()
        .find(|object| object.display_name == "com/example/Main.class")
        .unwrap();
    assert_eq!(class.kind, revx_core::ObjectKind::Binary);
    assert_eq!(class.format.as_deref(), Some("jvm_class"));
    assert!(
        class
            .analyses
            .iter()
            .any(|analysis| analysis.analyzer == "jvm_class_header")
    );
}

#[test]
fn analyzes_json_structure_for_virtual_and_physical_objects() {
    let dir = tempfile::tempdir().unwrap();
    let json_path = dir.path().join("config.json");
    std::fs::write(&json_path, br#"{"agent":true,"rules":[1,2,3]}"#).unwrap();

    let graph = revx_loader::identify_object_graph(&json_path, 0, 16).unwrap();
    let object = graph.objects.first().unwrap();
    let analysis = object
        .analyses
        .iter()
        .find(|analysis| analysis.analyzer == "json_structure")
        .unwrap();
    assert_eq!(analysis.status, revx_core::ObjectAnalysisStatus::Completed);
    assert_eq!(analysis.details["shape"], serde_json::json!("object"));
    assert!(
        analysis.details["keys"]
            .as_array()
            .unwrap()
            .iter()
            .any(|key| key == "agent")
    );
}

fn sample_wasm_module() -> Vec<u8> {
    vec![
        0x00, 0x61, 0x73, 0x6d, // magic
        0x01, 0x00, 0x00, 0x00, // version
        0x01, 0x09, 0x02, 0x60, 0x01, 0x7f, 0x00, 0x60, 0x00, 0x01, 0x7f, // type
        0x02, 0x0b, 0x01, 0x03, b'e', b'n', b'v', 0x03, b'l', b'o', b'g', 0x00,
        0x00, // import env.log func type 0
        0x03, 0x02, 0x01, 0x01, // function type index 1
        0x05, 0x03, 0x01, 0x00, 0x01, // memory min 1
        0x07, 0x10, 0x02, 0x03, b'r', b'u', b'n', 0x00, 0x01, 0x06, b'm', b'e', b'm', b'o', b'r',
        b'y', 0x02, 0x00, // exports
        0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2a, 0x0b, // code: i32.const 42
        0x0b, 0x08, 0x01, 0x00, 0x41, 0x00, 0x0b, 0x02, b'h', b'i', // data
    ]
}

fn sample_shell_link() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x4c];
    write_le_u32(&mut bytes, 0, 0x4c);
    bytes[4..20].copy_from_slice(&[
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ]);
    write_le_u32(&mut bytes, 20, 0x0000_00ba);
    write_le_u32(&mut bytes, 24, 0x20);
    write_le_u32(&mut bytes, 60, 1);

    let link_info = sample_shell_link_info();
    bytes.extend_from_slice(&link_info);
    append_lnk_string(&mut bytes, "powershell.exe");
    append_lnk_string(&mut bytes, "%TEMP%");
    append_lnk_string(
        &mut bytes,
        "-NoP -EncodedCommand SQBFAFgA http://example.invalid/payload",
    );
    append_lnk_environment_block(
        &mut bytes,
        "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\run.lnk",
    );
    write_le_u32_vec(&mut bytes, 0);
    bytes
}

fn sample_safetensors_model() -> Vec<u8> {
    let tensors = [
        ("model.embed_tokens.weight", "F16", vec![2, 3], 12usize),
        (
            "model.layers.0.self_attn.q_proj.weight",
            "F32",
            vec![2, 2],
            16usize,
        ),
        ("adapter.lora_A.weight", "F16", vec![1, 2], 4usize),
    ];
    let mut offset = 0usize;
    let mut entries = Vec::new();
    for (name, dtype, shape, byte_len) in tensors {
        let start = offset;
        offset += byte_len;
        entries.push((name, dtype, shape, start, offset));
    }
    let mut header = serde_json::Map::new();
    header.insert(
        "__metadata__".to_string(),
        serde_json::json!({
            "format": "pt",
            "adapter": "lora",
            "source": "unit-test",
        }),
    );
    for (name, dtype, shape, start, end) in entries {
        header.insert(
            name.to_string(),
            serde_json::json!({
                "dtype": dtype,
                "shape": shape,
                "data_offsets": [start, end],
            }),
        );
    }
    let header_bytes = serde_json::to_vec(&serde_json::Value::Object(header)).unwrap();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(header_bytes.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&header_bytes);
    bytes.extend(std::iter::repeat_n(0x42u8, offset));
    bytes
}

fn sample_safetensors_index() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "metadata": {
            "total_size": 32,
        },
        "weight_map": {
            "model.embed_tokens.weight": "model-00001-of-00002.safetensors",
            "model.layers.0.self_attn.q_proj.weight": "model-00002-of-00002.safetensors",
            "adapter.lora_A.weight": "model-00002-of-00002.safetensors",
        },
    }))
    .unwrap()
}

fn sample_gguf_model() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"GGUF");
    append_u32(&mut bytes, 3);
    append_u64(&mut bytes, 2);
    append_u64(&mut bytes, 4);
    append_gguf_string(&mut bytes, "general.architecture");
    append_u32(&mut bytes, 8);
    append_gguf_string(&mut bytes, "llama");
    append_gguf_string(&mut bytes, "general.name");
    append_u32(&mut bytes, 8);
    append_gguf_string(&mut bytes, "Tiny LoRA");
    append_gguf_string(&mut bytes, "general.alignment");
    append_u32(&mut bytes, 4);
    append_u32(&mut bytes, 32);
    append_gguf_string(&mut bytes, "tokenizer.ggml.tokens");
    append_u32(&mut bytes, 9);
    append_u32(&mut bytes, 8);
    append_u64(&mut bytes, 2);
    append_gguf_string(&mut bytes, "<s>");
    append_gguf_string(&mut bytes, "</s>");
    append_gguf_tensor(&mut bytes, "token_embd.weight", &[2, 3], 1, 0);
    append_gguf_tensor(&mut bytes, "adapter.lora_A.weight", &[1, 2], 2, 32);
    while bytes.len() % 32 != 0 {
        bytes.push(0);
    }
    bytes.extend(std::iter::repeat_n(0x44u8, 64));
    bytes
}

fn sample_pytorch_zip_model() -> Vec<u8> {
    let cursor = std::io::Cursor::new(Vec::new());
    let mut zip = zip::ZipWriter::new(cursor);
    let options: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default();
    zip.start_file("archive/data.pkl", options).unwrap();
    zip.write_all(sample_pickle_payload().as_slice()).unwrap();
    zip.start_file("archive/version", options).unwrap();
    zip.write_all(b"3\n").unwrap();
    zip.start_file("archive/byteorder", options).unwrap();
    zip.write_all(b"little").unwrap();
    zip.start_file("archive/data/0", options).unwrap();
    zip.write_all(&[0u8; 16]).unwrap();
    zip.finish().unwrap().into_inner()
}

fn sample_pickle_payload() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0x80, 0x02]);
    bytes.extend_from_slice(b"ctorch._utils\n_rebuild_tensor_v2\n");
    bytes.extend_from_slice(b"U\x07storage");
    bytes.push(b'R');
    bytes.push(b'.');
    bytes
}

fn append_gguf_tensor(
    bytes: &mut Vec<u8>,
    name: &str,
    shape: &[u64],
    tensor_type: u32,
    offset: u64,
) {
    append_gguf_string(bytes, name);
    append_u32(bytes, shape.len() as u32);
    for dim in shape {
        append_u64(bytes, *dim);
    }
    append_u32(bytes, tensor_type);
    append_u64(bytes, offset);
}

fn append_gguf_string(bytes: &mut Vec<u8>, value: &str) {
    append_u64(bytes, value.len() as u64);
    bytes.extend_from_slice(value.as_bytes());
}

fn append_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn append_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn sample_shell_link_info() -> Vec<u8> {
    let mut info = vec![0u8; 36];
    let common_network_offset = 36u32;
    let network = sample_shell_link_network();
    let suffix_offset = common_network_offset + network.len() as u32;
    let suffix = b"payload.exe\0";
    let suffix_unicode_offset = suffix_offset + suffix.len() as u32;
    let suffix_unicode = utf16le_null("payload.exe");
    info.extend_from_slice(&network);
    info.extend_from_slice(suffix);
    info.extend_from_slice(&suffix_unicode);
    let info_size = info.len() as u32;
    write_le_u32(&mut info, 0, info_size);
    write_le_u32(&mut info, 4, 36);
    write_le_u32(&mut info, 8, 0x2);
    write_le_u32(&mut info, 20, common_network_offset);
    write_le_u32(&mut info, 24, suffix_offset);
    write_le_u32(&mut info, 32, suffix_unicode_offset);
    info
}

fn sample_shell_link_network() -> Vec<u8> {
    let mut network = vec![0u8; 28];
    let net_name_offset = 28u32;
    let net_name = b"\\\\fileserver\\share\0";
    let net_name_unicode_offset = net_name_offset + net_name.len() as u32;
    let net_name_unicode = utf16le_null("\\\\fileserver\\share");
    network.extend_from_slice(net_name);
    network.extend_from_slice(&net_name_unicode);
    let network_size = network.len() as u32;
    write_le_u32(&mut network, 0, network_size);
    write_le_u32(&mut network, 4, 0x2);
    write_le_u32(&mut network, 8, net_name_offset);
    write_le_u32(&mut network, 16, 0x0020_0000);
    write_le_u32(&mut network, 20, net_name_unicode_offset);
    network
}

fn append_lnk_string(bytes: &mut Vec<u8>, value: &str) {
    let units = value.encode_utf16().collect::<Vec<_>>();
    bytes.extend_from_slice(&(units.len() as u16).to_le_bytes());
    for unit in units {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
}

fn append_lnk_environment_block(bytes: &mut Vec<u8>, value: &str) {
    let size = 0x314usize;
    let start = bytes.len();
    bytes.resize(start + size, 0);
    write_le_u32(bytes, start, size as u32);
    write_le_u32(bytes, start + 4, 0xa000_0001);
    let ansi = value.as_bytes();
    bytes[start + 8..start + 8 + ansi.len()].copy_from_slice(ansi);
    let unicode = value.encode_utf16().collect::<Vec<_>>();
    for (index, unit) in unicode.iter().take(259).enumerate() {
        let offset = start + 268 + index * 2;
        bytes[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
    }
}

fn utf16le_null(value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for unit in value.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn write_le_u32_vec(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn sample_png_image() -> Vec<u8> {
    let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
    append_png_chunk(
        &mut bytes,
        b"IHDR",
        &[
            0, 0, 0, 2, // width
            0, 0, 0, 3, // height
            8, 2, 0, 0, 0,
        ],
    );
    append_png_chunk(&mut bytes, b"IDAT", &[0x78, 0x9c, 0x63, 0x00, 0x00]);
    append_png_chunk(&mut bytes, b"IEND", &[]);
    bytes
}

fn append_png_chunk(bytes: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    bytes.extend_from_slice(&(data.len() as u32).to_be_bytes());
    bytes.extend_from_slice(kind);
    bytes.extend_from_slice(data);
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(kind);
    hasher.update(data);
    bytes.extend_from_slice(&hasher.finalize().to_be_bytes());
}

fn sample_jpeg_image() -> Vec<u8> {
    let mut bytes = b"\xff\xd8".to_vec();
    append_jpeg_segment(&mut bytes, 0xe0, b"JFIF\0\x01\x02\0\0\x01\0\x01\0\0");
    append_jpeg_segment(
        &mut bytes,
        0xc0,
        &[8, 0, 5, 0, 4, 3, 1, 0x11, 0, 2, 0x11, 1, 3, 0x11, 1],
    );
    append_jpeg_segment(&mut bytes, 0xda, &[1, 1, 0, 0, 63, 0]);
    bytes.extend_from_slice(&[0x11, 0x22, 0x33]);
    bytes.extend_from_slice(b"\xff\xd9");
    bytes
}

fn append_jpeg_segment(bytes: &mut Vec<u8>, marker: u8, payload: &[u8]) {
    bytes.extend_from_slice(&[0xff, marker]);
    bytes.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
    bytes.extend_from_slice(payload);
}

fn sample_gif_image() -> Vec<u8> {
    let mut bytes = b"GIF89a".to_vec();
    bytes.extend_from_slice(&4u16.to_le_bytes());
    bytes.extend_from_slice(&5u16.to_le_bytes());
    bytes.extend_from_slice(&[0x80, 0x00, 0x00]);
    bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0xff, 0xff, 0xff]);
    bytes.push(0x2c);
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&4u16.to_le_bytes());
    bytes.extend_from_slice(&5u16.to_le_bytes());
    bytes.push(0x00);
    bytes.push(0x02);
    bytes.extend_from_slice(&[0x02, 0x4c, 0x01, 0x00]);
    bytes.push(0x3b);
    bytes
}

fn sample_ico_with_png_icon(png: &[u8]) -> Vec<u8> {
    let image_offset = 6 + 16;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&[16, 16, 0, 0]);
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&32u16.to_le_bytes());
    bytes.extend_from_slice(&(png.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(image_offset as u32).to_le_bytes());
    bytes.extend_from_slice(png);
    bytes
}

fn sample_bmp_file() -> Vec<u8> {
    let dib = sample_bmp_dib_payload(2, 2);
    let pixel_offset = 14 + dib_header_len(&dib);
    let mut bytes = b"BM".to_vec();
    bytes.extend_from_slice(&((14 + dib.len()) as u32).to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&(pixel_offset as u32).to_le_bytes());
    bytes.extend_from_slice(&dib);
    bytes
}

fn sample_ico_dib_payload() -> Vec<u8> {
    sample_bmp_dib_payload(16, 32)
}

fn sample_bmp_dib_payload(width: i32, height: i32) -> Vec<u8> {
    let row_stride = (((width as usize * 32) + 31) / 32) * 4;
    let pixel_bytes = row_stride * height.unsigned_abs() as usize;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&40u32.to_le_bytes());
    bytes.extend_from_slice(&width.to_le_bytes());
    bytes.extend_from_slice(&height.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&32u16.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&(pixel_bytes as u32).to_le_bytes());
    bytes.extend_from_slice(&2835i32.to_le_bytes());
    bytes.extend_from_slice(&2835i32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend(std::iter::repeat_n(0x7fu8, pixel_bytes));
    bytes
}

fn dib_header_len(dib: &[u8]) -> usize {
    u32::from_le_bytes([dib[0], dib[1], dib[2], dib[3]]) as usize
}

fn sample_ico_with_dib_icon(dib: &[u8]) -> Vec<u8> {
    let image_offset = 6 + 16;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&[16, 16, 0, 0]);
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&32u16.to_le_bytes());
    bytes.extend_from_slice(&(dib.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(image_offset as u32).to_le_bytes());
    bytes.extend_from_slice(dib);
    bytes
}

fn sample_webp_riff() -> Vec<u8> {
    let mut payload = b"WEBP".to_vec();
    let mut vp8x = vec![0x30, 0, 0, 0];
    vp8x.extend_from_slice(&1u32.to_le_bytes()[..3]);
    vp8x.extend_from_slice(&2u32.to_le_bytes()[..3]);
    append_riff_chunk(&mut payload, b"VP8X", &vp8x);
    append_riff_chunk(&mut payload, b"ICCP", b"abc");
    let mut bytes = b"RIFF".to_vec();
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&payload);
    bytes
}

fn append_riff_chunk(bytes: &mut Vec<u8>, id: &[u8; 4], data: &[u8]) {
    bytes.extend_from_slice(id);
    bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
    bytes.extend_from_slice(data);
    if data.len() % 2 == 1 {
        bytes.push(0);
    }
}

fn sample_pcap_capture() -> Vec<u8> {
    let packet = sample_ethernet_ipv4_tcp_packet();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    bytes.extend_from_slice(&2u16.to_le_bytes());
    bytes.extend_from_slice(&4u16.to_le_bytes());
    bytes.extend_from_slice(&0i32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&65_535u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&1_700_000_000u32.to_le_bytes());
    bytes.extend_from_slice(&123_456u32.to_le_bytes());
    bytes.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&packet);
    bytes
}

fn sample_pcapng_capture() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x0a0d0d0au32.to_le_bytes());
    bytes.extend_from_slice(&28u32.to_le_bytes());
    bytes.extend_from_slice(&0x1a2b3c4du32.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&(-1i64).to_le_bytes());
    bytes.extend_from_slice(&28u32.to_le_bytes());
    bytes
}

fn sample_ole_compound_file() -> Vec<u8> {
    const SECTOR_SIZE: usize = 512;
    let mut bytes = vec![0u8; SECTOR_SIZE * 5];
    bytes[0..8].copy_from_slice(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1");
    write_le_u16(&mut bytes, 24, 0x003e);
    write_le_u16(&mut bytes, 26, 0x0003);
    write_le_u16(&mut bytes, 28, 0xfffe);
    write_le_u16(&mut bytes, 30, 9);
    write_le_u16(&mut bytes, 32, 6);
    write_le_u32(&mut bytes, 44, 1);
    write_le_u32(&mut bytes, 48, 0);
    write_le_u32(&mut bytes, 56, 4096);
    write_le_u32(&mut bytes, 60, 3);
    write_le_u32(&mut bytes, 64, 1);
    write_le_u32(&mut bytes, 68, 0xffff_fffe);
    write_le_u32(&mut bytes, 72, 0);
    write_le_u32(&mut bytes, 76, 1);
    for index in 1..109 {
        write_le_u32(&mut bytes, 76 + index * 4, 0xffff_ffff);
    }

    let fat_offset = SECTOR_SIZE * 2;
    for index in 0..(SECTOR_SIZE / 4) {
        write_le_u32(&mut bytes, fat_offset + index * 4, 0xffff_ffff);
    }
    write_le_u32(&mut bytes, fat_offset, 0xffff_fffe);
    write_le_u32(&mut bytes, fat_offset + 4, 0xffff_fffd);
    write_le_u32(&mut bytes, fat_offset + 8, 0xffff_fffe);
    write_le_u32(&mut bytes, fat_offset + 12, 0xffff_fffe);
    write_le_u32(&mut bytes, fat_offset + 16, 0xffff_fffe);

    let mini_fat_offset = SECTOR_SIZE * 4;
    for index in 0..(SECTOR_SIZE / 4) {
        write_le_u32(&mut bytes, mini_fat_offset + index * 4, 0xffff_ffff);
    }
    write_le_u32(&mut bytes, mini_fat_offset, 0xffff_fffe);
    write_le_u32(&mut bytes, mini_fat_offset + 4, 0xffff_fffe);

    let directory_offset = SECTOR_SIZE;
    write_cfb_dir_entry(
        &mut bytes[directory_offset..directory_offset + 128],
        "Root Entry",
        5,
        0xffff_ffff,
        0xffff_ffff,
        1,
        2,
        128,
    );
    write_cfb_dir_entry(
        &mut bytes[directory_offset + 128..directory_offset + 256],
        "VBA",
        1,
        0xffff_ffff,
        3,
        2,
        0xffff_fffe,
        0,
    );
    write_cfb_dir_entry(
        &mut bytes[directory_offset + 256..directory_offset + 384],
        "dir",
        2,
        0xffff_ffff,
        0xffff_ffff,
        0xffff_ffff,
        0,
        18,
    );
    write_cfb_dir_entry(
        &mut bytes[directory_offset + 384..directory_offset + 512],
        "SummaryInformation",
        2,
        0xffff_ffff,
        0xffff_ffff,
        0xffff_ffff,
        1,
        23,
    );
    bytes[SECTOR_SIZE * 3..SECTOR_SIZE * 3 + 18].copy_from_slice(b"VBA macro metadata");
    bytes[SECTOR_SIZE * 3 + 64..SECTOR_SIZE * 3 + 64 + 23]
        .copy_from_slice(b"summary metadata stream");
    bytes
}

fn write_cfb_dir_entry(
    entry: &mut [u8],
    name: &str,
    object_type: u8,
    left: u32,
    right: u32,
    child: u32,
    start_sector: u32,
    stream_size: u64,
) {
    let mut utf16 = name.encode_utf16().collect::<Vec<_>>();
    utf16.push(0);
    for (index, unit) in utf16.iter().take(32).enumerate() {
        entry[index * 2..index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
    }
    write_le_u16(entry, 64, (utf16.len().min(32) * 2) as u16);
    entry[66] = object_type;
    entry[67] = 1;
    write_le_u32(entry, 68, left);
    write_le_u32(entry, 72, right);
    write_le_u32(entry, 76, child);
    write_le_u32(entry, 116, start_sector);
    write_le_u64(entry, 120, stream_size);
}

fn write_le_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_le_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_le_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn sample_ethernet_ipv4_tcp_packet() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    bytes.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    bytes.extend_from_slice(&0x0800u16.to_be_bytes());
    bytes.push(0x45);
    bytes.push(0);
    bytes.extend_from_slice(&40u16.to_be_bytes());
    bytes.extend_from_slice(&0x1234u16.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.push(64);
    bytes.push(6);
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&[192, 0, 2, 1]);
    bytes.extend_from_slice(&[198, 51, 100, 2]);
    bytes.extend_from_slice(&12345u16.to_be_bytes());
    bytes.extend_from_slice(&443u16.to_be_bytes());
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.push(0x50);
    bytes.push(0x02);
    bytes.extend_from_slice(&64240u16.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes
}

fn sample_pdf_document() -> Vec<u8> {
    let objects = [
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>\nendobj\n",
        "4 0 obj\n<< /Length 44 >>\nstream\nBT /F1 12 Tf 72 720 Td (Hello ReVX) Tj ET\nendstream\nendobj\n",
        "5 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert('revx')) >>\nendobj\n",
    ];
    let mut bytes = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for object in objects {
        offsets.push(bytes.len());
        bytes.extend_from_slice(object.as_bytes());
    }
    let xref_offset = bytes.len();
    bytes.extend_from_slice(format!("xref\n0 {}\n", offsets.len() + 1).as_bytes());
    bytes.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets {
        bytes.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    bytes.extend_from_slice(
        format!("trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n").as_bytes(),
    );
    bytes
}


#[test]
fn identifies_universal_media_and_text_formats() {
    let dir = tempfile::tempdir().expect("tempdir");

    let cases: &[(&str, &[u8], &str, revx_core::ObjectKind)] = &[
        (
            "sample.cab",
            b"MSCF\0\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\x03\x01\x01\0\x01\0\x01\0",
            "cab",
            revx_core::ObjectKind::Archive,
        ),
        ("photo.tif", b"II*\0\x08\0\0\0", "tiff", revx_core::ObjectKind::Image),
        ("audio.flac", b"fLaC\0\0\0\x22", "flac", revx_core::ObjectKind::File),
        ("track.ogg", b"OggS\0\x02", "ogg", revx_core::ObjectKind::File),
        (
            "clip.mp4",
            b"\0\0\0\x18ftypisom\0\0\x02\0isomiso2",
            "mp4",
            revx_core::ObjectKind::File,
        ),
        ("font.woff", b"wOFF\0\x01\0\0", "woff", revx_core::ObjectKind::File),
        ("font.woff2", b"wOF2\0\x01\0\0", "woff2", revx_core::ObjectKind::File),
        (
            "disk.qcow2",
            b"QFI\xfb\0\0\0\x03",
            "qcow2",
            revx_core::ObjectKind::FilesystemImage,
        ),
        (
            "cert.pem",
            b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
            "pem",
            revx_core::ObjectKind::Text,
        ),
        (
            "page.html",
            b"<!DOCTYPE html><html><body>hi</body></html>\n",
            "html",
            revx_core::ObjectKind::Text,
        ),
        (
            "payload.bin",
            br#"{"alpha":1,"beta":[true,false]}"#,
            "json",
            revx_core::ObjectKind::Text,
        ),
        (
            "config.noext",
            b"<?xml version=\"1.0\"?><root attr=\"1\"/>\n",
            "xml",
            revx_core::ObjectKind::Text,
        ),
    ];

    for (name, bytes, format, kind) in cases {
        let path = dir.path().join(name);
        std::fs::write(&path, *bytes).expect("write sample");
        let graph = revx_loader::identify_object_graph(&path, 0, 1).expect("load object graph");
        let root = graph
            .objects
            .iter()
            .find(|object| {
                object
                    .path
                    .as_deref()
                    .is_some_and(|value| value.ends_with(name))
            })
            .unwrap_or_else(|| &graph.objects[0]);
        assert_eq!(root.format.as_deref(), Some(*format), "format for {name}");
        assert_eq!(root.kind, *kind, "kind for {name}");
    }
}

#[test]
fn profiles_unknown_binary_blobs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("opaque.bin");
    let mut bytes = vec![0u8; 256];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = ((index * 37) % 251) as u8;
    }
    std::fs::write(&path, &bytes).expect("write opaque");
    let graph = revx_loader::identify_object_graph(&path, 0, 1).expect("load");
    let root = &graph.objects[0];
    assert_eq!(root.format.as_deref(), Some("unknown"));
    assert!(
        root.analyses
            .iter()
            .any(|analysis| analysis.analyzer == "unknown_blob_profile"),
        "analyses={:?}",
        root.analyses
            .iter()
            .map(|a| &a.analyzer)
            .collect::<Vec<_>>()
    );
}

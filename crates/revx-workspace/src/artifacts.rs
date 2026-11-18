use super::*;

impl Workspace {
    pub fn read_artifact_preview(
        &self,
        relative_path: Option<&str>,
        hash_blake3: Option<&str>,
        offset: u64,
        max_bytes: usize,
    ) -> Result<ArtifactReadResponse> {
        use std::io::{Read, Seek, SeekFrom};
        let relative_path = resolve_artifact_relative_path(relative_path, hash_blake3)?;
        validate_artifact_relative_path(&relative_path)?;
        let path = self.root.join(&relative_path);
        let mut file = fs::File::open(&path)
            .with_context(|| format!("failed to read artifact {}", relative_path))?;
        let total_size = file.metadata()?.len();
        let capped = max_bytes.clamp(1, 1_048_576) as u64;
        let start = offset.min(total_size);
        file.seek(SeekFrom::Start(start))?;
        let mut preview = Vec::new();
        Read::by_ref(&mut file)
            .take(capped)
            .read_to_end(&mut preview)?;
        let end = start.saturating_add(preview.len() as u64);
        let hash = match relative_path.strip_prefix("artifacts/") {
            Some(name) if name.len() == 64 && name.chars().all(|ch| ch.is_ascii_hexdigit()) => {
                name.to_string()
            }
            _ => {
                let mut hasher = blake3::Hasher::new();
                file.seek(SeekFrom::Start(0))?;
                let mut chunk = vec![0u8; 64 * 1024];
                loop {
                    let n = file.read(&mut chunk)?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&chunk[..n]);
                }
                hasher.finalize().to_hex().to_string()
            }
        };
        let artifact = ArtifactHandle {
            hash_blake3: hash,
            relative_path,
            size: total_size,
            content_type: artifact_content_type(&preview),
        };
        Ok(ArtifactReadResponse {
            artifact,
            offset,
            total_size,
            returned_size: preview.len(),
            truncated: end < total_size,
            preview_hex: hex::encode(&preview),
            preview_text: text_preview(&preview),
        })
    }

    pub(crate) fn write_artifact_bytes(
        &self,
        content_type: &str,
        bytes: &[u8],
    ) -> Result<ArtifactHandle> {
        let hash = blake3::hash(bytes).to_hex().to_string();
        let relative_path = format!("artifacts/{hash}");
        let path = self.root.join(&relative_path);
        let needs_write = match fs::metadata(&path) {
            Ok(meta) => meta.len() != bytes.len() as u64,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => true,
            Err(err) => return Err(err.into()),
        };
        if needs_write {
            let artifacts_dir = self.root.join("artifacts");
            fs::create_dir_all(&artifacts_dir)?;
            let tmp = artifacts_dir.join(format!(".tmp-{}-{}", std::process::id(), hash));
            let write_result = (|| -> Result<()> {
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&tmp)?;
                file.write_all(bytes)?;
                file.sync_all()?;
                Ok(())
            })();
            if let Err(err) = write_result {
                let _ = fs::remove_file(&tmp);
                return Err(err);
            }
            if let Err(err) = fs::rename(&tmp, &path) {
                let _ = fs::remove_file(&tmp);
                return Err(err.into());
            }
        }
        Ok(ArtifactHandle {
            hash_blake3: hash,
            relative_path,
            size: bytes.len() as u64,
            content_type: content_type.to_string(),
        })
    }
}

pub(crate) fn resolve_artifact_relative_path(
    relative_path: Option<&str>,
    hash_blake3: Option<&str>,
) -> Result<String> {
    match (relative_path, hash_blake3) {
        (Some(path), _) if !path.trim().is_empty() => Ok(path.trim().to_string()),
        (_, Some(hash)) if !hash.trim().is_empty() => {
            let hash = hash.trim();
            if hash.len() != 64 || !hash.chars().all(|ch| ch.is_ascii_hexdigit()) {
                anyhow::bail!("invalid blake3 artifact hash: {hash}");
            }
            Ok(format!("artifacts/{hash}"))
        }
        _ => anyhow::bail!("artifact read requires relative_path or hash_blake3"),
    }
}

pub(crate) fn validate_artifact_relative_path(relative_path: &str) -> Result<()> {
    let path = Path::new(relative_path);
    if path.is_absolute() {
        anyhow::bail!("artifact relative_path must be relative");
    }
    let mut components = path.components();
    match components.next() {
        Some(std::path::Component::Normal(prefix)) if prefix == "artifacts" => {}
        _ => anyhow::bail!("artifact relative_path must start with artifacts/"),
    }
    for component in components {
        match component {
            std::path::Component::Normal(_) => {}
            _ => anyhow::bail!("artifact relative_path contains invalid component"),
        }
    }
    Ok(())
}

pub(crate) fn artifact_handle_from_db(
    hash_blake3: String,
    relative_path: String,
    size: i64,
    content_type: &str,
) -> ArtifactHandle {
    ArtifactHandle {
        hash_blake3,
        relative_path,
        size: size.max(0) as u64,
        content_type: content_type.to_string(),
    }
}

pub(crate) fn optional_artifact_handle_from_db(
    hash_blake3: Option<String>,
    relative_path: Option<String>,
    size: Option<i64>,
    content_type: &str,
) -> Option<ArtifactHandle> {
    let hash_blake3 = hash_blake3?;
    Some(ArtifactHandle {
        hash_blake3,
        relative_path: relative_path.unwrap_or_default(),
        size: size.unwrap_or_default().max(0) as u64,
        content_type: content_type.to_string(),
    })
}

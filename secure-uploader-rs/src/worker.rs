use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use sha2::{Sha256, Digest};
use std::sync::Arc;
use crate::config::AppState;
use tracing::error;

pub fn spawn_hash_worker(
    file_path: PathBuf,
    state: Arc<AppState>,
    uuid: String,
    username: String,
) {
    tokio::spawn(async move {
        let mut f = match File::open(&file_path).await {
            Ok(file) => file,
            Err(e) => {
                error!("Failed to open file for hashing {:?}: {}", file_path, e);
                return;
            }
        };

        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];
        
        loop {
            match f.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => hasher.update(&buffer[..n]),
                Err(e) => {
                    error!("Hash worker read error on {:?}: {}", file_path, e);
                    return;
                }
            }
        }
        
        let hash = format!("{:x}", hasher.finalize());
        let specific_path = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("unknown").to_string();
        
        let _ = state.db.log_audit_event(
            "file_uploaded",
            Some(&uuid),
            Some(&username),
            Some(&format!("file: {}, sha256: {}", specific_path, hash)),
            None
        );
    });
}

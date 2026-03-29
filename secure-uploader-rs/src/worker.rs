use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use sha2::{Sha256, Digest};
use std::sync::Arc;
use crate::config::AppState;
use tracing::{error, info};

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
        
        // Calculate relative path from the user's upload directory
        let folder = crate::utils::sanitize_folder_name(&username).unwrap_or(uuid.clone());
        let user_upload_root = PathBuf::from(crate::config::UPLOAD_ROOT).join(&folder);
        
        let specific_path = match file_path.strip_prefix(&user_upload_root) {
            Ok(rel) => rel.to_str().unwrap_or("unknown").replace('\\', "/"),
            Err(_) => file_path.file_name().and_then(|n| n.to_str()).unwrap_or("unknown").to_string(),
        };

        // Record the hash for future deduplication
        if let Err(e) = state.db.record_file_hash(&hash, &uuid, &specific_path) {
            error!("Failed to record file hash for {}: {}", specific_path, e);
        }

        info!(
            "File {} (hash: {}) processed for user {}",
            specific_path,
            hash,
            username
        );
    });
}

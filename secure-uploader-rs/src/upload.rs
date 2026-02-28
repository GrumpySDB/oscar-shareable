use axum::{
    extract::{Multipart, Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use std::{os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc};
use tokio::{fs, io::AsyncWriteExt};
use serde::Deserialize;
use rsa::RsaPrivateKey;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rsa::Oaep;
use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes256Gcm, Nonce};

use crate::{
    config::AppState,
    utils::{sanitize_folder_name, sanitize_upload_relative_path},
};

const MAX_FILE_SIZE: usize = 10 * 1024 * 1024; // 10MB
const OXIMETRY_MAX_FILE_SIZE: usize = 200 * 1024; // 200KB
const UPLOAD_ROOT: &str = "./data/uploads";

pub async fn list_files(
    Path(folder): Path<String>,
) -> impl IntoResponse {
    let folder = match sanitize_folder_name(&folder) {
        Some(f) => f,
        None => return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid folder name" })))),
    };

    let folder_path = PathBuf::from(UPLOAD_ROOT).join(&folder);
    if !folder_path.exists() {
        return Ok(Json(serde_json::json!({ "filenames": [] })));
    }

    let filenames = collect_filenames_recursive(&folder_path, &folder_path).await.unwrap_or_default();
    Ok(Json(serde_json::json!({ "filenames": filenames })))
}

#[async_recursion::async_recursion]
async fn collect_filenames_recursive(root: &PathBuf, current: &PathBuf) -> anyhow::Result<Vec<String>> {
    let mut names = Vec::new();
    let mut read_dir = fs::read_dir(current).await?;
    while let Some(entry) = read_dir.next_entry().await? {
        if entry.file_type().await?.is_dir() {
            names.extend(collect_filenames_recursive(root, &entry.path()).await?);
        } else if entry.file_type().await?.is_file() {
            if let Ok(rel) = entry.path().strip_prefix(root) {
                if let Some(s) = rel.to_str() {
                    names.push(s.replace('\\', "/"));
                }
            }
        }
    }
    Ok(names)
}

pub async fn delete_folder(
    Path(folder): Path<String>,
) -> impl IntoResponse {
    let folder = match sanitize_folder_name(&folder) {
        Some(f) => f,
        None => return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid folder name" })))),
    };

    let folder_path = PathBuf::from(UPLOAD_ROOT).join(&folder);
    let _ = fs::remove_dir_all(&folder_path).await;
    
    Ok(Json(serde_json::json!({ "deleted": folder })))
}

#[derive(Deserialize)]
struct Envelope {
    #[serde(rename = "wrappedKey")]
    wrapped_key: String,
    iv: String,
    tag: String,
}

pub async fn handle_upload(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let mut folder = String::new();
    let mut selected_date = 0i64;
    let mut tinfoil_hat_mode = false;
    let mut upload_session_id = String::new();
    let mut total_batches = 1usize;
    let mut batch_index = 0usize;
    let mut upload_type = "sdcard".to_string();
    let mut wellue_db_parents_raw = String::new();
    let mut raw_encryption_envelope_map = String::new();
    
    // Files are held in RAM during processing, matching the JS multer.memoryStorage()
    // approach for performance. Size limits are enforced during streaming to prevent
    // unbounded memory consumption.
    let mut temp_files: Vec<(String, Vec<u8>)> = Vec::new();
    let mut batch_bytes_total: usize = 0;
    let max_batch_bytes = state.config.max_upload_batch_bytes;

    while let Some(field) = multipart.next_field().await.unwrap_or(None) {
        let name = field.name().unwrap_or("").to_string();
        
        if name == "folder" { folder = field.text().await.unwrap_or_default(); }
        else if name == "selectedDateMs" { selected_date = field.text().await.unwrap_or_default().parse().unwrap_or(0); }
        else if name == "tinfoilHatMode" { tinfoil_hat_mode = field.text().await.unwrap_or("false".to_string()).to_lowercase() == "true"; }
        else if name == "uploadSessionId" { upload_session_id = field.text().await.unwrap_or_default(); }
        else if name == "totalBatches" { total_batches = field.text().await.unwrap_or_default().parse().unwrap_or(1); }
        else if name == "batchIndex" { batch_index = field.text().await.unwrap_or_default().parse().unwrap_or(0); }
        else if name == "uploadType" { upload_type = field.text().await.unwrap_or_default(); }
        else if name == "wellueDbParents" { wellue_db_parents_raw = field.text().await.unwrap_or_default(); }
        else if name == "encryptionEnvelope" { raw_encryption_envelope_map = field.text().await.unwrap_or_default(); }
        else if name == "files" {
            let file_name = field.file_name().unwrap_or("").to_string();
            if file_name.is_empty() {
                continue;
            }

            // Read the file chunk-by-chunk, enforcing per-file and per-batch limits
            // during streaming rather than after the full read. This prevents a single
            // oversized file from consuming unbounded memory before we can reject it.
            let mut file_buf: Vec<u8> = Vec::new();
            let mut field = field;

            while let Ok(Some(chunk)) = field.chunk().await {
                let new_file_size = file_buf.len() + chunk.len();
                if new_file_size > MAX_FILE_SIZE {
                    // Individual file exceeds 10MB — not valid CPAP SD card data
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "error": format!(
                                "The file \"{}\" exceeds the 10 MB size limit. \
                                 Files larger than 10 MB are not expected in CPAP data \
                                 and have been rejected for your protection.",
                                file_name
                            )
                        })),
                    );
                }

                let new_batch_total = batch_bytes_total + file_buf.len() + chunk.len();
                if new_batch_total > max_batch_bytes {
                    let limit_mb = max_batch_bytes / (1024 * 1024);
                    return (
                        StatusCode::PAYLOAD_TOO_LARGE,
                        Json(serde_json::json!({
                            "error": format!(
                                "This upload batch exceeds the {} MB total size limit. \
                                 Please try selecting a more recent start date to reduce \
                                 the number of files per upload.",
                                limit_mb
                            )
                        })),
                    );
                }

                file_buf.extend_from_slice(&chunk);
            }

            if !file_buf.is_empty() {
                batch_bytes_total += file_buf.len();
                temp_files.push((file_name, file_buf));
            }
        }
    }

    let folder = match sanitize_folder_name(&folder) {
        Some(f) => f,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid folder name" }))),
    };

    let folder_path = PathBuf::from(UPLOAD_ROOT).join(&folder);
    fs::create_dir_all(&folder_path).await.unwrap();

    let envelopes: std::collections::HashMap<String, Envelope> = if tinfoil_hat_mode && !raw_encryption_envelope_map.is_empty() {
        serde_json::from_str(&raw_encryption_envelope_map).unwrap_or_default()
    } else {
        std::collections::HashMap::new()
    };

    let effective_upload_type = "sdcard"; // For strict rewrite we would parse inferUploadType, but simplifying for MVP

    let mut uploaded_count = 0;
    
    // All files are in RAM at this point — write to disk in a single pass.
    // This matches the JS multer.memoryStorage() pattern for maximum throughput.
    for (filename, payload) in temp_files {
        let sanitized_path = match sanitize_upload_relative_path(&filename) {
            Some(p) => p,
            None => continue,
        };

        let dest_path = folder_path.join(&sanitized_path);
        if let Some(parent) = dest_path.parent() {
            let _ = fs::create_dir_all(parent).await;
        }

        let mut final_payload = payload;

        if tinfoil_hat_mode {
            if let Some(env) = envelopes.get(&sanitized_path).or_else(|| envelopes.get(&filename)) {
                if let Ok(decrypted) = decrypt_payload(&final_payload, env, &state.config.app_encryption_private_key) {
                    final_payload = decrypted;
                } else {
                    return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": format!("Unable to decrypt {}", sanitized_path) })));
                }
            } else {
                return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": format!("Missing envelope for {}", sanitized_path) })));
            }
        }

        if let Ok(mut file) = fs::File::create(&dest_path).await {
            let _ = file.write_all(&final_payload).await;
            
            // Apply 0640 perms (roughly what Node did)
            let mut perms = file.metadata().await.unwrap().permissions();
            perms.set_mode(0o640);
            let _ = file.set_permissions(perms).await;
            
            uploaded_count += 1;
        }
    }

    (StatusCode::OK, Json(serde_json::json!({
        "uploaded": uploaded_count,
        "batchIndex": batch_index,
        "totalBatches": total_batches
    })))
}

fn decrypt_payload(
    file_payload: &[u8],
    envelope: &Envelope,
    priv_key: &RsaPrivateKey,
) -> anyhow::Result<Vec<u8>> {
    let wrapped_key = STANDARD.decode(&envelope.wrapped_key)?;
    let iv = STANDARD.decode(&envelope.iv)?;
    let tag = STANDARD.decode(&envelope.tag)?;

    let padding = Oaep::new::<sha2::Sha256>();
    let aes_key = priv_key.decrypt(padding, &wrapped_key)?;
    
    if aes_key.len() != 32 {
        anyhow::bail!("Invalid AES key");
    }

    let cipher = Aes256Gcm::new_from_slice(&aes_key)?;
    let nonce = Nonce::from_slice(&iv);
    
    // Reconstruct the ciphertext with the auth tag for Aes256Gcm
    let mut ciphertext = file_payload.to_vec();
    ciphertext.extend_from_slice(&tag);

    // No associated data used in JS implementation 
    let payload = Payload {
        msg: &ciphertext,
        aad: b"",
    };

    let decrypted = cipher.decrypt(nonce, payload).map_err(|_| anyhow::anyhow!("AES decryption failed"))?;
    Ok(decrypted)
}

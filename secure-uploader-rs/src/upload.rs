use axum::{
    extract::{State, Request},
    http::{header, StatusCode},
    response::{IntoResponse, Json},
    Extension,
};
use multer::{Constraints, Multipart as MulterMultipart, SizeLimit};
use std::{path::PathBuf, sync::Arc};
use tokio::{fs, io::AsyncWriteExt};
use serde::Deserialize;
use rsa::RsaPrivateKey;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rsa::Oaep;
use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes256Gcm, Nonce};
use bollard::container::{StopContainerOptions, RemoveContainerOptions};
use regex::{Regex, Captures};

use crate::{
    auth::Claims,
    config::AppState,
    utils::sanitize_upload_relative_path,
};

const MAX_FILE_SIZE: usize = 10 * 1024 * 1024; // 10MB
use crate::config::{UPLOAD_ROOT, PROFILE_ROOT};

pub async fn list_files(
    Extension(claims): Extension<Claims>,
) -> impl IntoResponse {
    let folder = crate::utils::sanitize_folder_name(&claims.username).unwrap_or(claims.uuid.clone());

    let folder_path = PathBuf::from(UPLOAD_ROOT).join(&folder);
    if !folder_path.exists() {
        return Json(serde_json::json!({ "filenames": [] }));
    }

    let filenames = collect_filenames_recursive(&folder_path, &folder_path).await.unwrap_or_default();
    Json(serde_json::json!({ "filenames": filenames }))
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
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> impl IntoResponse {
    let folder = crate::utils::sanitize_folder_name(&claims.username).unwrap_or(claims.uuid.clone());

    // 1. Evict active OSCAR containers (primary and guest) if they exist
    {
        let mut to_cleanup = Vec::new();
        let uuid_param = claims.uuid.clone();
        
        state.active_containers.retain(|_, info| {
            if info.owner_uuid == uuid_param {
                to_cleanup.push(info.container_id.clone());
                false
            } else {
                true
            }
        });

        for cid in to_cleanup {
            let state_clone = state.clone();
            let upid = uuid_param.clone();
            tokio::spawn(async move {
                crate::proxy::cleanup_oscar_session(state_clone, upid, cid).await;
            });
        }
    }

    // 2. Erase files
    let upload_path = PathBuf::from(UPLOAD_ROOT).join(&folder);
    let profile_path = PathBuf::from(PROFILE_ROOT).join(&folder);
    let app_config_path = PathBuf::from(&state.config.app_config_root).join(&folder);
    
    let _ = fs::remove_dir_all(&upload_path).await;
    let _ = fs::remove_dir_all(&profile_path).await;
    let _ = fs::remove_dir_all(app_config_path).await;

    // 3. Recreate template profile (Fresh Start)
    let u_name = claims.username.clone();
    let uuid_clone = claims.uuid.clone();
    let config_clone = state.config.clone();
    let _ = tokio::task::spawn_blocking(move || {
        if let Err(e) = crate::auth::create_user_profile(&u_name, &uuid_clone, &config_clone) {
            tracing::error!("Failed to recreate template files for user {} after deletion: {}", u_name, e);
        }
    }).await;
    
    Json(serde_json::json!({ "deleted": folder }))
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
    Extension(claims): Extension<Claims>,
    req: Request,
) -> impl IntoResponse {
    let boundary = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|ct| ct.to_str().ok())
        .and_then(|ct| multer::parse_boundary(ct).ok())
        .ok_or((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Invalid or missing multipart boundary" })),
        ));

    let boundary = match boundary {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };

    // Explicitly set constraints to bypass Axum's hidden 2MB per-field limit.
    // We allow up to 10MB per field (MAX_FILE_SIZE) and a total limit for the whole batch.
    let constraints = Constraints::new()
        .size_limit(
            SizeLimit::new()
                .per_field(MAX_FILE_SIZE as u64)
                .whole_stream(state.config.max_upload_batch_bytes as u64)
        );

    let stream = req.into_body().into_data_stream();
    let mut multipart = MulterMultipart::with_constraints(stream, boundary, constraints);

    let username_folder = crate::utils::sanitize_folder_name(&claims.username).unwrap_or(claims.uuid.clone());
    let mut provided_folder = String::new();
    let mut tinfoil_hat_mode = false;
    let mut total_batches = 1usize;
    let mut batch_index = 0usize;
    let mut total_files = 0usize;
    let mut total_bytes_grand = 0u64;
    let mut upload_type = String::new();
    let mut raw_encryption_envelope_map = String::new();

    // Files are held in RAM during processing, matching the JS multer.memoryStorage()
    // approach for performance. Size limits are enforced during streaming to prevent
    // unbounded memory consumption.
    let mut temp_files: Vec<(String, Vec<u8>)> = Vec::new();
    let mut batch_bytes_total: usize = 0;
    let max_batch_bytes = state.config.max_upload_batch_bytes;

    loop {
        let field = match multipart.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(e) => {
                tracing::error!("Multipart error: {}", e);
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": format!("Multipart parsing error: {}", e) })),
                ).into_response();
            }
        };

        let name = field.name().unwrap_or("").to_string();
        
        if name == "folder" {
            provided_folder = field.text().await.unwrap_or_default();
        } else if matches!(name.as_str(), "selectedDateMs" | "uploadSessionId" | "wellueDbParents") {
            let _ = field.text().await;
        } else if name == "tinfoilHatMode" {
            tinfoil_hat_mode = field.text().await.unwrap_or_else(|_| "false".to_string()).to_lowercase() == "true";
        } else if name == "totalBatches" {
            total_batches = field.text().await.unwrap_or_default().parse().unwrap_or(1);
        } else if name == "batchIndex" {
            batch_index = field.text().await.unwrap_or_default().parse().unwrap_or(0);
        } else if name == "totalFiles" {
            total_files = field.text().await.unwrap_or_default().parse().unwrap_or(0);
        } else if name == "totalBytes" {
            total_bytes_grand = field.text().await.unwrap_or_default().parse().unwrap_or(0);
        } else if name == "uploadType" {
            upload_type = field.text().await.unwrap_or_default();
        } else if name == "encryptionEnvelope" {
            raw_encryption_envelope_map = field.text().await.unwrap_or_default();
        }
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

            loop {
                match field.chunk().await {
                    Ok(Some(chunk)) => {
                        let new_file_size = file_buf.len() + chunk.len();

                        if new_file_size > MAX_FILE_SIZE {
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
                            ).into_response();
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
                            ).into_response();
                        }

                        file_buf.extend_from_slice(&chunk);
                    }
                    Ok(None) => {
                        break; // EOF
                    }
                    Err(e) => {
                        tracing::error!("Error reading multipart chunk for file {}: {}", file_name, e);
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({
                                "error": format!(
                                    "Failed to read file \"{}\" during upload. Connection may have been interrupted or a limit was hit: {}",
                                    file_name,
                                    e
                                )
                            })),
                        ).into_response();
                    }
                }
            }

            if !file_buf.is_empty() {
                batch_bytes_total += file_buf.len();
                temp_files.push((file_name, file_buf));
            }
        }
    }

    // Resolve subfolder name
    let subfolder = if claims.sid.starts_with("api_key_") {
        let id_str = &claims.sid["api_key_".len()..];
        if let Ok(id) = id_str.parse::<i64>() {
            let label = state.db.get_api_key_label(id).ok().flatten().unwrap_or_else(|| "default".to_string());
            format!("api-{}", label)
        } else {
            "api-unknown".to_string()
        }
    } else if !provided_folder.is_empty() {
        // Sanitize: alphanumeric, hyphen, underscore only
        let re = Regex::new(r"[^a-zA-Z0-9_-]").unwrap();
        re.replace_all(&provided_folder, "").to_string()
    } else {
        "uploads".to_string()
    };

    let folder_path = if upload_type == "wellue-spo2" || upload_type == "spo2" {
        PathBuf::from(UPLOAD_ROOT).join(&username_folder).join("Oximetry").join(&subfolder)
    } else {
        PathBuf::from(UPLOAD_ROOT).join(&username_folder).join(&subfolder)
    };
    fs::create_dir_all(&folder_path).await.unwrap();

    let envelopes: std::collections::HashMap<String, Envelope> = if tinfoil_hat_mode && !raw_encryption_envelope_map.is_empty() {
        serde_json::from_str(&raw_encryption_envelope_map).unwrap_or_default()
    } else {
        std::collections::HashMap::new()
    };

    // --- Validate paths and decrypt payloads synchronously first ---
    // This ensures all security checks are done before any file touches disk,
    // and lets us return clean error responses if anything is wrong.
    
    // --- Pre-validate dataset requirements (Issue 2/3: Incremental Sync and Philips Support) ---
    if upload_type == "sdcard" {
        let mut has_str_edf = false;
        let mut has_ident_crc = false;
        
        for (filename, _) in &temp_files {
            let lower = filename.to_lowercase();
            if lower.ends_with("str.edf") { has_str_edf = true; }
            if lower.ends_with("identification.crc") { has_ident_crc = true; }
        }
        
        if !has_ident_crc {
            let str_on_disk = folder_path.join("STR.edf").exists() || folder_path.join("SD_CARD/STR.edf").exists();
            if has_str_edf || str_on_disk {
                let ident_on_disk = folder_path.join("Identification.crc").exists() || folder_path.join("SD_CARD/Identification.crc").exists();
                if !ident_on_disk {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "error": "Missing Identification.crc for initial ResMed upload."
                        }))
                    ).into_response();
                }
            }
        }
    }

    let mut write_tasks: Vec<(PathBuf, Vec<u8>)> = Vec::with_capacity(temp_files.len());

    for (filename, payload) in temp_files {
        let sanitized_path = match sanitize_upload_relative_path(&filename) {
            Some(p) => p,
            None => continue,
        };

        let dest_path = folder_path.join(&sanitized_path);

        let mut final_payload = payload;

        if tinfoil_hat_mode {
            if let Some(env) = envelopes.get(&sanitized_path).or_else(|| envelopes.get(&filename)) {
                match decrypt_payload(&final_payload, env, &state.config.app_encryption_private_key) {
                    Ok(decrypted) => {
                        final_payload = decrypted;
                    }
                    Err(_) => {
                        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": format!("Unable to decrypt {}. Tinfoil Hat Mode envelope mismatch or corrupt payload.", sanitized_path) }))).into_response();
                    }
                }
            } else {
                tracing::warn!("Tinfoil Hat Mode: Missing envelope entry for file: {} (original filename: {})", sanitized_path, filename);
                return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ 
                    "error": format!("Missing encryption envelope for {}. Please ensure your uploader is sending matching metadata for all files.", sanitized_path) 
                }))).into_response();
            }
        }

        if !crate::validation::validate_upload_content(&dest_path, &final_payload) {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": format!("Validation failed for file {}", sanitized_path) }))).into_response();
        }

        let hash_dest = dest_path.clone();
        let hash_state = state.clone();
        let hash_uuid = claims.uuid.clone();
        let hash_username = claims.username.clone();

        write_tasks.push((dest_path, final_payload));
        crate::worker::spawn_hash_worker(hash_dest, hash_state, hash_uuid, hash_username);
    }

    // --- Create parent directories for all destination paths ---
    // Done in a single pass before spawning write tasks to avoid concurrent mkdir races.
    for (dest_path, _) in &write_tasks {
        if let Some(parent) = dest_path.parent() {
            let _ = fs::create_dir_all(parent).await;
            #[cfg(unix)]
            {
                use std::os::unix::fs::chown;
                let _ = chown(parent, Some(911), Some(911));
            }
        }
    }
    
    // Also chown the root folder itself
    #[cfg(unix)]
    {
        use std::os::unix::fs::chown;
        let _ = chown(&folder_path, Some(911), Some(911));
    }

    // --- Write all files to disk in parallel, bounded to 32 concurrent writes ---
    // Using JoinSet with a concurrency cap avoids overwhelming the filesystem while
    // providing large throughput gains for CPAP batches of hundreds of small files.
    use tokio::task::JoinSet;

    const MAX_CONCURRENT_WRITES: usize = 32;
    let mut join_set: JoinSet<bool> = JoinSet::new();
    let mut uploaded_count = 0usize;

    for (dest_path, payload) in write_tasks {
        // Drain completed tasks when we hit the concurrency cap
        while join_set.len() >= MAX_CONCURRENT_WRITES {
            if let Some(Ok(true)) = join_set.join_next().await {
                uploaded_count += 1;
            }
        }

        join_set.spawn(async move {
            // Set mode 0o640 at file creation
            let file = tokio::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o660)
                .open(&dest_path)
                .await;

            match file {
                Ok(mut f) => {
                    let success = f.write_all(&payload).await.is_ok();
                    let _ = f.flush().await; // Ensure write finishes before chown
                    
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::chown;
                        // Chown file to UID 911, GID 911 for OSCAR consumption
                        let _ = chown(&dest_path, Some(911), Some(911));
                    }
                    success
                },
                Err(e) => {
                    tracing::error!("Failed to create file {:?}: {}", dest_path, e);
                    false
                },
            }
        });
    }

    // --- Final Drain of JoinSet ---
    // Critical: Without this final loop, the remaining tasks in the JoinSet (up to MAX_CONCURRENT_WRITES)
    // would be aborted when the JoinSet is dropped at the end of this function.
    while let Some(res) = join_set.join_next().await {
        if let Ok(true) = res {
            uploaded_count += 1;
        }
    }

    // --- Update Profile.xml if this is an SD card upload ---
    if (upload_type == "sdcard" || upload_type == "wellue-spo2" || upload_type == "spo2") && batch_index + 1 == total_batches {
        let username_dir = crate::utils::sanitize_folder_name(&claims.username).unwrap_or(claims.uuid.clone());
        let profile_xml_path = PathBuf::from(PROFILE_ROOT)
            .join(&username_dir)
            .join("Profiles")
            .join(&username_dir)
            .join("Profile.xml");

        if profile_xml_path.exists() {
            if upload_type == "sdcard" {
                let new_path = format!("/config/Documents/SDCARD/{}", subfolder);
                let _ = update_last_cpap_path(&profile_xml_path, &new_path).await;
            } else {
                let new_path = format!("/config/Documents/SDCARD/Oximetry/{}", subfolder);
                let _ = update_last_oximetry_path(&profile_xml_path, &new_path).await;
            }
        }
    }

    if batch_index + 1 == total_batches {
        let _ = state.db.log_audit_event(
            "upload_completed",
            Some(&claims.uuid),
            Some(&claims.username),
            Some(&format!("files: {}, total_size: {} bytes", total_files, total_bytes_grand)),
            None
        );
    }

    (StatusCode::OK, Json(serde_json::json!({
        "uploaded": uploaded_count,
        "batchIndex": batch_index,
        "totalBatches": total_batches
    }))).into_response()
}

pub async fn update_last_cpap_path(path: &std::path::Path, new_value: &str) -> std::io::Result<()> {
    crate::utils::force_xml_setting(path, "LastCPAPPath", "QString", new_value, None).await?;
    Ok(())
}

pub async fn update_last_oximetry_path(path: &std::path::Path, new_value: &str) -> std::io::Result<()> {
    crate::utils::force_xml_setting(path, "LastOximetryPath", "QString", new_value, None).await?;
    Ok(())
}

pub async fn list_banner_images() -> impl IntoResponse {
    let mut images = Vec::new();
    let images_root = "./public/images";
    if let Ok(mut entries) = fs::read_dir(images_root).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            if let Some(name) = entry.file_name().to_str() {
                if name.ends_with(".webp") {
                    images.push(name.to_string());
                }
            }
        }
    }
    
    // Sort for deterministic results (optional but nice)
    images.sort();
    
    Json(serde_json::json!({ "images": images }))
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

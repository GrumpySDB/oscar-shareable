use axum::{
    extract::{Path, State, Multipart},
    http::{StatusCode, HeaderMap},
    response::{IntoResponse, Json},
    body::Bytes,
    Extension,
};
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use std::path::PathBuf;
use serde::Deserialize;
use uuid::Uuid;
use bollard::container::{StopContainerOptions, RemoveContainerOptions};

use crate::{
    auth::Claims,
    config::{AppState, UPLOAD_ROOT},
};

#[derive(Deserialize, Default)]
pub struct CreateSessionPayload {
    pub device_id: Option<serde_json::Value>,
    pub import_type: Option<String>,
}

pub async fn create_session_handler(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let mut payload = CreateSessionPayload::default();

    if !body.is_empty() {
        let content_type = headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");

        if content_type.contains("application/json") {
            if let Ok(p) = serde_json::from_slice(&body) {
                payload = p;
            }
        } else if content_type.contains("application/x-www-form-urlencoded") {
            if let Ok(p) = serde_urlencoded::from_bytes(&body) {
                payload = p;
            }
        }
    }

    let import_type = payload.import_type.unwrap_or_else(|| "sdcard".to_string());
    let device_id_str = payload.device_id.map(|v| match v {
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s,
        _ => v.to_string(),
    });
    
    // Enforce 1 active session per user
    // 1. Check for existing active session - instead of erroring, we automatically cancel old ones
    // for this user to allow the firmware to recover from crashes/reboots effortlessly.
    if let Err(e) = state.db.cancel_active_sync_sessions(&claims.uuid) {
        tracing::error!("Failed to cancel old sync sessions for user {}: {}", claims.uuid, e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Database error" }))).into_response();
    }

    let id = match state.db.create_sync_session(&claims.uuid, device_id_str.as_deref(), &import_type) {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("Failed to create sync session: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Database error" }))).into_response();
        }
    };

    // Return SleepHQ-compatible structure
    (StatusCode::CREATED, Json(serde_json::json!({ 
        "data": {
            "id": id,
            "type": "imports",
            "attributes": {
                "id": id,
                "status": "active"
            }
        }
    }))).into_response()
}

pub async fn upload_file_handler(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<i64>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    // 1. Verify session ownership and status
    let session = match state.db.get_sync_session_by_id(id) {
        Ok(Some(s)) => s,
        _ => return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "Session not found" }))).into_response(),
    };

    if session["user_uuid"] != claims.uuid || session["status"] != "active" {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "Invalid or inactive session" }))).into_response();
    }

    let mut client_hash = String::new();
    let mut sanitized_rel_dir = String::new();
    let mut original_file_name = String::new();
    let mut temp_path: Option<PathBuf> = None;
    let mut computed_hash = String::new();

    // 2. Parse Multipart
    while let Ok(Some(mut field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        if name == "path" {
            let path_str = field.text().await.unwrap_or_default();
            if let Some(p) = crate::utils::sanitize_upload_relative_path(&path_str) {
                sanitized_rel_dir = p;
            } else {
                if let Some(tp) = temp_path { let _ = fs::remove_file(tp).await; }
                return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid directory path" }))).into_response();
            }
        } else if name == "name" {
            // Firmware may send "name" field with the filename
            original_file_name = field.text().await.unwrap_or_default();
        } else if name == "content_hash" {
            client_hash = field.text().await.unwrap_or_default();
        } else if name == "file" {
            if original_file_name.is_empty() {
                original_file_name = field.file_name().unwrap_or("").to_string();
            }

            // 3. Setup Temp File & Hashing
            let folder = crate::utils::sanitize_folder_name(&claims.username).unwrap_or(claims.uuid.clone());
            let upload_dir = PathBuf::from(UPLOAD_ROOT).join(&folder);
            
            // Ensure user upload dir exists
            if let Err(e) = fs::create_dir_all(&upload_dir).await {
                tracing::error!("Failed to create upload dir: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "FileSystem error" }))).into_response();
            }

            let t_path = upload_dir.join(format!(".upload.{}.tmp", Uuid::new_v4()));
            let file = match fs::File::create(&t_path).await {
                Ok(f) => f,
                Err(e) => {
                    tracing::error!("Failed to create tmp file {:?}: {}", t_path, e);
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "FileSystem error" }))).into_response();
                }
            };
            temp_path = Some(t_path.clone());
            
            let mut writer = tokio::io::BufWriter::new(file);
            let mut context = md5::Context::new();
            let mut total_bytes = 0;

            // 4. Stream Chunks to Disk
            while let Ok(Some(chunk)) = field.chunk().await {
                total_bytes += chunk.len();
                if total_bytes > 10 * 1024 * 1024 {
                    let _ = fs::remove_file(&t_path).await;
                    return (StatusCode::PAYLOAD_TOO_LARGE, Json(serde_json::json!({ "error": "File too large (max 10MB)" }))).into_response();
                }
                
                context.consume(&chunk);
                if let Err(e) = writer.write_all(&chunk).await {
                    tracing::error!("Failed to write chunk: {}", e);
                    let _ = fs::remove_file(&t_path).await;
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "FileSystem error" }))).into_response();
                }
            }

            if let Err(e) = writer.flush().await {
                tracing::error!("Failed to flush writer: {}", e);
                let _ = fs::remove_file(&t_path).await;
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "FileSystem error" }))).into_response();
            }

            // Sync with firmware: MD5(file_content + filename)
            context.consume(original_file_name.as_bytes());
            computed_hash = format!("{:x}", context.compute());
        }
    }

    // 5. Finalization
    if original_file_name.is_empty() || temp_path.is_none() {
        if let Some(tp) = temp_path { let _ = fs::remove_file(tp).await; }
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Missing filename or file content" }))).into_response();
    }

    let tp = temp_path.unwrap();
    let folder = crate::utils::sanitize_folder_name(&claims.username).unwrap_or(claims.uuid.clone());
    
    // Construct final path: root / user / dir / filename
    let mut final_path = PathBuf::from(UPLOAD_ROOT).join(&folder);
    if !sanitized_rel_dir.is_empty() {
        final_path = final_path.join(&sanitized_rel_dir);
    }
    
    // Sanitize the filename one more time to be sure
    let safe_filename = match crate::utils::sanitize_upload_relative_path(&original_file_name) {
        Some(s) if !s.contains('/') => s,
        _ => {
            let _ = fs::remove_file(&tp).await;
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid filename" }))).into_response();
        }
    };
    final_path = final_path.join(&safe_filename);

    // 6. Integrity check
    if !client_hash.is_empty() && client_hash != computed_hash {
        let _ = fs::remove_file(&tp).await;
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "MD5 Integrity check failed" }))).into_response();
    }

    // 7. Validation
    let payload_to_validate = match fs::read(&tp).await {
        Ok(p) => p,
        Err(_) => {
            let _ = fs::remove_file(&tp).await;
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Validation read error" }))).into_response();
        }
    };

    if !crate::validation::validate_upload_content(&final_path, &payload_to_validate) {
        let _ = fs::remove_file(&tp).await;
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Validation failed" }))).into_response();
    }

    // 8. Atomic Rename and Permissions
    if let Some(parent) = final_path.parent() {
        let _ = fs::create_dir_all(parent).await;
    }

    if let Err(e) = fs::rename(&tp, &final_path).await {
        tracing::error!("Failed to rename {:?} to {:?}: {}", tp, final_path, e);
        let _ = fs::remove_file(&tp).await;
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "FileSystem error" }))).into_response();
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::chown;
        let _ = chown(&final_path, Some(911), Some(911));
        if let Some(parent) = final_path.parent() {
            let _ = chown(parent, Some(911), Some(911));
        }
    }

    // 10. Record file hash
    let rel_path = if sanitized_rel_dir.is_empty() {
        safe_filename.clone()
    } else {
        format!("{}/{}", sanitized_rel_dir, safe_filename)
    };
    let _ = state.db.record_file_hash(&computed_hash, &claims.uuid, &rel_path);
    let _ = state.db.increment_sync_session_files(id);

    (StatusCode::CREATED, Json(serde_json::json!({ "status": "received" }))).into_response()
}

pub async fn process_files_handler(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    // 1. Verify session
    let session = match state.db.get_sync_session_by_id(id) {
        Ok(Some(s)) => s,
        _ => return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "Session not found" }))).into_response(),
    };

    if session["user_uuid"] != claims.uuid || session["status"] != "active" {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "Invalid or inactive session" }))).into_response();
    }

    // 2. Finalize Session
    if let Err(e) = state.db.update_sync_session_status(id, "completed") {
        tracing::error!("Failed to complete session: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Database error" }))).into_response();
    }

    // 3. Trigger Container Eviction
    let uuid = claims.uuid.clone();
    let docker = state.docker.clone();
    let state_arc = state.clone();

    tokio::spawn(async move {
        if let Some((_, info)) = state_arc.active_containers.remove(&uuid) {
            tracing::info!("Evicting OSCAR container {} due to API sync completion.", info.container_id);
            let _ = docker.stop_container(&info.container_id, None::<StopContainerOptions>).await;
            let _ = docker.remove_container(&info.container_id, Some(RemoveContainerOptions { force: true, ..Default::default() })).await;
        }
    });

    let _ = state.db.log_audit_event(
        "api_sync_completed",
        Some(&claims.uuid),
        Some(&claims.username),
        Some(&format!("session_id: {}, files: {}", id, session["files_processed"])),
        None
    );

    (StatusCode::OK, Json(serde_json::json!({ "status": "complete" }))).into_response()
}

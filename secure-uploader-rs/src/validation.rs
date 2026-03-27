use std::path::Path;


use tracing::warn;

pub fn validate_upload_content(file_path: &Path, payload: &[u8]) -> bool {
    let extension = file_path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
    
    if extension == "crc" && payload.len() > 1024 { return false; }
    if extension == "json" && payload.len() > 10 * 1024 * 1024 { return false; } 
    
    match extension.as_str() {
        "db" => validate_sqlite(payload),
        "edf" => validate_edf(payload),
        "zip" | "pdf" | "json" | "xml" | "spo2" | "tgt" | "crc" | "txt" | "seq" | "bin" | "o2" | "log" => true,
        ext if ext.chars().all(char::is_numeric) => true,
        _ => {
            warn!("Rejected unknown file extension in fast-path validation: {}", extension);
            false 
        }
    }
}

fn validate_sqlite(payload: &[u8]) -> bool {
    if payload.len() < 16 { return false; }
    &payload[0..16] == b"SQLite format 3\0"
}

fn validate_edf(payload: &[u8]) -> bool {
    if payload.len() < 256 { return false; }
    let version = &payload[0..8];
    version.iter().all(|c| c.is_ascii())
}

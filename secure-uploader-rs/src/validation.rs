use std::path::Path;


use tracing::warn;

pub fn validate_upload_content(file_path: &Path, payload: &[u8]) -> bool {
    let extension = file_path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
    
    // Size constraints based on import type (deduced from extension for now)
    // CPAP files max 10MB, Oximetry files max 200KB.
    match extension.as_str() {
        "edf" | "json" | "xml" | "txt" | "log" | "bin" => {
            if payload.len() > 10 * 1024 * 1024 { return false; }
        }
        "spo2" | "tgt" | "o2" => {
            if payload.len() > 200 * 1024 { return false; }
        }
        "crc" => {
            if payload.len() > 1024 { return false; }
        }
        _ => {}
    }

    match extension.as_str() {
        "db" => validate_sqlite(payload),
        "edf" => validate_edf(payload),
        "json" => validate_json(payload),
        "spo2" => validate_spo2(payload),
        "tgt" => validate_tgt(payload),
        "wellue" => validate_wellue(payload),
        "xml" | "txt" | "seq" | "bin" | "o2" | "log" | "crc" => true,
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

fn validate_json(payload: &[u8]) -> bool {
    let trimmed = payload.iter().find(|&&b| b != 0 && !b.is_ascii_whitespace());
    match trimmed {
        Some(b) => *b == b'{' || *b == b'[',
        None => false,
    }
}

fn validate_spo2(payload: &[u8]) -> bool {
    if payload.len() < 2 { return false; }
    payload.starts_with(b"X\x03")
}

fn validate_tgt(payload: &[u8]) -> bool {
    let trimmed = payload.iter().find(|&&b| b != 0 && !b.is_ascii_whitespace());
    match trimmed {
        Some(b) => *b == b'#',
        None => false,
    }
}

fn validate_wellue(payload: &[u8]) -> bool {
    if payload.len() < 2 { return false; }
    payload.starts_with(b"\x01\x03")
}

use sha2::Sha256;

pub fn safe_equal(a: &str, b: &str) -> bool {
    // Basic timing safe equality for strings
    // In Rust, comparing strings is not inherently timing-safe.
    // We can use a simple constant time compare from `subtle` crate or just hash them, 
    // but the `constant_time_eq` crate is usually used. 
    // Since we don't have it in dependencies, we'll hash both with same secret and compare.
    use sha2::Digest;
    let mut hasher1 = Sha256::new();
    hasher1.update(a.as_bytes());
    let h1 = hasher1.finalize();

    let mut hasher2 = Sha256::new();
    hasher2.update(b.as_bytes());
    let h2 = hasher2.finalize();

    h1 == h2
}

pub fn sanitize_folder_name(value: &str) -> Option<String> {
    let normalized = value.trim();
    if normalized.is_empty() || normalized.len() > 64 {
        return None;
    }
    for c in normalized.chars() {
        if !c.is_ascii_alphanumeric() && c != '_' && c != '-' {
            return None;
        }
    }
    Some(normalized.to_string())
}

pub fn sanitize_upload_relative_path(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > 512 {
        return None;
    }
    if value.contains('\0') {
        return None;
    }
    let normalized = value.replace('\\', "/");
    // VERY simple normalization
    if normalized == "." || normalized.starts_with('/') || normalized.starts_with("../") || normalized.contains("/../") {
        return None;
    }
    
    let segments: Vec<&str> = normalized.split('/').collect();
    for seg in &segments {
        if seg.is_empty() || *seg == "." || *seg == ".." || seg.len() > 255 {
            return None;
        }
    }
    
    Some(segments.join("/"))
}

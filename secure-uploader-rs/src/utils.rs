use sha2::Sha256;

pub fn safe_equal(a: &str, b: &str) -> bool {
    // Timing-safe comparison for strings of equal length.
    // Use hash-based comparison to handle variable lengths safely.
    use sha2::Digest;
    let mut hasher1 = Sha256::new();
    hasher1.update(a.as_bytes());
    let h1 = hasher1.finalize();

    let mut hasher2 = Sha256::new();
    hasher2.update(b.as_bytes());
    let h2 = hasher2.finalize();

    // Comparing fixed-length hashes is timing-safe
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
    if value.is_empty() || value.len() > 1024 {
        return None;
    }

    // Replace all backslashes with forward slashes immediately
    let mut path_str = value.replace('\\', "/");

    // Strip leading slashes and dots to treat as relative path
    while path_str.starts_with('/') || path_str.starts_with("./") {
        if path_str.starts_with('/') {
            path_str = path_str[1..].to_string();
        } else {
            path_str = path_str[2..].to_string();
        }
    }

    // Deny fundamental traversal indicators and null bytes
    if path_str.contains('\0') || path_str.contains("..") {
        return None;
    }

    if path_str.is_empty() {
        return Some("".to_string());
    }

    let segments: Vec<&str> = path_str.split('/').collect();
    let mut cleaned_segments = Vec::new();

    for seg in segments {
        let trimmed = seg.trim();
        // Reject empty segments (except if it's the only one and we already handled empty above), 
        // dots, hidden files, or overly long segment names
        if trimmed.is_empty() || trimmed == "." || trimmed == ".." || trimmed.starts_with('.') || trimmed.len() > 255 {
            return None;
        }

        // Enforce strict character whitelist for each segment:
        // Alphanumeric, underscores, hyphens, spaces, and a single period (for extensions)
        if !trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == ' ') {
            return None;
        }

        // Prevent multiple consecutive dots within a filename (e.g. "file..txt")
        if trimmed.contains("..") {
            return None;
        }

        cleaned_segments.push(trimmed);
    }

    if cleaned_segments.is_empty() {
        return None;
    }

    Some(cleaned_segments.join("/"))
}

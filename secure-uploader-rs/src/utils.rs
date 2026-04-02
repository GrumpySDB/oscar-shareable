use sha2::{Sha256, Digest};
use regex::{Regex, Captures};
use tokio::fs;

pub fn safe_equal(a: &str, b: &str) -> bool {
    // Timing-safe comparison for strings of equal length.
    // Use hash-based comparison to handle variable lengths safely.
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

pub async fn force_xml_setting(path: &std::path::Path, key: &str, _val_type: &str, value: &str, init_template: Option<&str>) -> std::io::Result<bool> {
    let mut was_initialized = false;
    let content = match fs::read_to_string(path).await {
        Ok(c) => c,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                if let Some(template) = init_template {
                    if let Some(parent) = path.parent() {
                        fs::create_dir_all(parent).await?;
                    }
                    fs::write(path, template).await?;
                    was_initialized = true;
                    template.to_string()
                } else {
                    return Ok(false); // No template, no file, nothing changed
                }
            } else {
                return Err(e);
            }
        }
    };

    // Use a non-greedy, dot-all regex to match the tag regardless of attribute order or whitespace
    let pattern = format!(r#"(?s)(<{}\s*[^>]*>)(.*?)(</{}>)"#, key, key);
    let re = Regex::new(&pattern).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    
    let mut found = false;
    let updated = re.replace(&content, |caps: &Captures| {
        found = true;
        format!("{}{}{}", &caps[1], value, &caps[3])
    });

    if updated != content {
        fs::write(path, updated.as_ref()).await?;
        tracing::info!("Forced XML setting {} in {:?} to {}", key, path, value);
        Ok(true)
    } else if !found {
        tracing::debug!("XML setting element <{}> not found in {:?}", key, path);
        Ok(was_initialized) // If we initialized the file, treat it as a change
    } else {
        tracing::debug!("XML setting element <{}> in {:?} was already set to {}", key, path, value);
        Ok(was_initialized) // If we initialized the file and it happens to match, it's still a change from "nothing"
    }
}

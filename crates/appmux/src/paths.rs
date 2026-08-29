use std::path::PathBuf;

pub fn root() -> PathBuf {
    PathBuf::from(std::env::var_os("LOCALAPPDATA").expect("LOCALAPPDATA is not set")).join("AppMux")
}

pub fn instances_file() -> PathBuf {
    root().join("instances.json")
}

pub fn config_file() -> PathBuf {
    root().join("config.json")
}

pub fn user_recipes_file() -> PathBuf {
    root().join("recipes.json")
}

pub fn instances_dir() -> PathBuf {
    root().join("Instances")
}

/// Sanitize a user-visible name into a filesystem/registry-safe token.
pub fn sanitize(s: &str) -> String {
    let out: String = s
        .trim()
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c.to_ascii_lowercase()
            } else if c == ' ' {
                '-'
            } else {
                '_'
            }
        })
        .collect();
    if out.is_empty() {
        "app".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_names() {
        assert_eq!(sanitize("Client A"), "client-a");
        assert_eq!(sanitize("Notepad++"), "notepad__");
        assert_eq!(sanitize("  Work_1  "), "work_1");
        assert_eq!(sanitize("///"), "___");
        assert_eq!(sanitize(""), "app");
    }
}

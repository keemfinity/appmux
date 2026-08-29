//! Guardrails: refuse to containerize apps that ship anti-cheat/DRM or other
//! kernel components. Detection is heuristic and errs on the side of declining.

use std::path::Path;

const MARKERS: &[&str] = &[
    "easyanticheat",
    "battleye",
    "beservice",
    "vanguard",
    "vgc.exe",
    "vgk.sys",
    "faceit",
    "xigncode",
    "punkbuster",
    "anticheat",
    "denuvo",
];

/// Returns a human-readable reason if the target must be declined.
pub fn check(exe: &Path, hint: &str) -> Option<String> {
    let exe_name = exe
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    for m in MARKERS {
        if exe_name.contains(m) || hint.contains(m) {
            return Some(format!("target matches anti-cheat/DRM marker '{m}'"));
        }
    }
    // Scan the install directory (top level + one sublevel) for known markers.
    if let Some(dir) = exe.parent() {
        if let Some(reason) = scan_dir(dir, 1) {
            return Some(reason);
        }
    }
    None
}

fn scan_dir(dir: &Path, depth: u32) -> Option<String> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        for m in MARKERS {
            if name.contains(m) {
                return Some(format!(
                    "install directory contains anti-cheat/DRM component '{}'",
                    entry.file_name().to_string_lossy()
                ));
            }
        }
        if depth > 0 && entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            if let Some(r) = scan_dir(&entry.path(), depth - 1) {
                return Some(r);
            }
        }
    }
    None
}

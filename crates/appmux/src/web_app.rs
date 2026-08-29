use crate::store::Instance;
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

fn candidates() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for base in [
        std::env::var_os("ProgramFiles(x86)"),
        std::env::var_os("ProgramFiles"),
        std::env::var_os("LOCALAPPDATA"),
    ]
    .into_iter()
    .flatten()
    {
        let base = PathBuf::from(base);
        paths.push(base.join(r"Microsoft\Edge\Application\msedge.exe"));
        paths.push(base.join(r"Google\Chrome\Application\chrome.exe"));
    }
    paths
}

pub fn find_browser() -> Result<PathBuf> {
    candidates()
        .into_iter()
        .find(|path| path.exists())
        .context("Microsoft Edge or Google Chrome is required for App Web mode")
}

fn validate_url(value: &str) -> Result<()> {
    anyhow::ensure!(
        value.starts_with("https://")
            && value.len() <= 2048
            && !value.chars().any(char::is_control),
        "App Web URL must be a valid HTTPS URL"
    );
    Ok(())
}

pub fn launch(instance: &Instance) -> Result<u32> {
    let url = instance
        .web_url
        .as_deref()
        .context("App Web instance has no URL")?;
    validate_url(url)?;
    let browser = find_browser()?;
    let profile = instance.data_dir().join("Browser");
    std::fs::create_dir_all(&profile)?;
    let child = std::process::Command::new(&browser)
        .arg(format!("--user-data-dir={}", profile.display()))
        .arg(format!("--app={url}"))
        .args([
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-default-apps",
        ])
        .current_dir(browser.parent().unwrap_or(Path::new(r"C:\")))
        .spawn()
        .with_context(|| format!("launching {} in App Web mode", browser.display()))?;
    Ok(child.id())
}

pub fn stop(instance: &Instance) -> Result<()> {
    let profile = instance.data_dir().join("Browser");
    let script = crate::paths::root().join("web-instance-stop.ps1");
    std::fs::write(
        &script,
        "param([string]$Profile)\n$ErrorActionPreference='Stop'\nGet-CimInstance Win32_Process | Where-Object { $_.Name -in @('msedge.exe','chrome.exe') -and $_.CommandLine -and $_.CommandLine.IndexOf($Profile,[StringComparison]::OrdinalIgnoreCase) -ge 0 } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }\n",
    )?;
    let output = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&script)
        .arg("-Profile")
        .arg(profile.to_string_lossy().to_string())
        .output()?;
    if !output.status.success() {
        bail!(
            "stopping App Web processes failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_urls_are_accepted() {
        assert!(validate_url("https://chatgpt.com/").is_ok());
        assert!(validate_url("http://chatgpt.com/").is_err());
        assert!(validate_url("javascript:alert(1)").is_err());
        assert!(validate_url("https://example.com/\nattack").is_err());
    }
}

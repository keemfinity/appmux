//! Resolve .lnk shortcuts via IShellLinkW (documented COM API, no shell UI).

use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};
use windows::core::{Interface, PCWSTR};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, IPersistFile, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED,
    STGM_READ,
};
use windows::Win32::UI::Shell::{IShellLinkW, ShellLink, SLGP_RAWPATH};

pub struct LnkInfo {
    pub target: PathBuf,
    pub args: String,
    pub workdir: Option<PathBuf>,
}

fn wide(p: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    p.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn from_buf(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

pub fn resolve(path: &Path) -> Result<LnkInfo> {
    unsafe {
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)?;
        let pf: IPersistFile = link.cast()?;
        let wpath = wide(path);
        pf.Load(PCWSTR(wpath.as_ptr()), STGM_READ)?;

        let mut buf = [0u16; 4096];
        link.GetPath(&mut buf, std::ptr::null_mut(), SLGP_RAWPATH.0 as u32)?;
        let target_raw = from_buf(&buf);
        if target_raw.is_empty() {
            return Err(anyhow!("shortcut has no file target: {}", path.display()));
        }
        // SLGP_RAWPATH may return env-var form like %ProgramFiles%\...
        let target = PathBuf::from(expand_env(&target_raw));

        let mut abuf = [0u16; 4096];
        link.GetArguments(&mut abuf)?;
        let args = from_buf(&abuf);

        let mut wbuf = [0u16; 4096];
        link.GetWorkingDirectory(&mut wbuf)?;
        let wd = from_buf(&wbuf);
        let workdir = if wd.is_empty() {
            None
        } else {
            Some(PathBuf::from(expand_env(&wd)))
        };

        Ok(LnkInfo {
            target,
            args,
            workdir,
        })
    }
}

/// Expand %VAR% references using the current environment.
fn expand_env(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        if let Some(end) = after.find('%') {
            let name = &after[..end];
            match std::env::var(name) {
                Ok(v) => out.push_str(&v),
                Err(_) => {
                    out.push('%');
                    out.push_str(name);
                    out.push('%');
                }
            }
            rest = &after[end + 1..];
        } else {
            out.push('%');
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_known_vars() {
        std::env::set_var("MI_TEST_VAR", "C:\\Base");
        assert_eq!(expand_env("%MI_TEST_VAR%\\app.exe"), "C:\\Base\\app.exe");
        assert_eq!(expand_env("no vars here"), "no vars here");
        assert_eq!(expand_env("%UNSET_VAR_XYZ%\\x"), "%UNSET_VAR_XYZ%\\x");
        assert_eq!(expand_env("50%"), "50%");
    }
}

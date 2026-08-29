//! Create per-instance desktop shortcuts. Pinning to the taskbar cannot be
//! automated (Windows reserves that for the user), but a desktop shortcut
//! with its own AppUserModelID can be pinned by hand and groups separately.

use crate::store::Instance;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use windows::core::{Interface, PCWSTR, PROPVARIANT};
use windows::Win32::Storage::EnhancedStorage::PKEY_AppUserModel_ID;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, IPersistFile, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED,
};
use windows::Win32::UI::Shell::PropertiesSystem::IPropertyStore;
use windows::Win32::UI::Shell::{
    FOLDERID_Desktop, IShellLinkW, SHGetKnownFolderPath, ShellLink, KF_FLAG_DEFAULT,
};

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn desktop_dir() -> Result<PathBuf> {
    unsafe {
        let path = SHGetKnownFolderPath(&FOLDERID_Desktop, KF_FLAG_DEFAULT, None)?;
        let s = path.to_string()?;
        Ok(PathBuf::from(s))
    }
}

/// Creates "<Display> - <Instance>.lnk" on the desktop. Returns the path.
pub fn create(inst: &Instance, display: &str, icon_exe: &Path) -> Result<PathBuf> {
    let launcher = std::env::current_exe()?.with_file_name("appmuxw.exe");
    let launcher = if launcher.exists() {
        launcher
    } else {
        std::env::current_exe()?
    };

    let file_name = format!("{display} - {}.lnk", inst.name);
    let out = desktop_dir()?.join(&file_name);

    unsafe {
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)?;

        let target = wide(&launcher.to_string_lossy());
        link.SetPath(PCWSTR(target.as_ptr()))?;

        let args = format!(
            "run --target \"{}\" --app \"{}\" --instance \"{}\"",
            inst.app_path, inst.app_id, inst.name
        );
        let args_w = wide(&args);
        link.SetArguments(PCWSTR(args_w.as_ptr()))?;

        let icon_w = wide(&icon_exe.to_string_lossy());
        link.SetIconLocation(PCWSTR(icon_w.as_ptr()), 0)?;

        let desc = wide(&format!("AppMux: {display} ({})", inst.name));
        link.SetDescription(PCWSTR(desc.as_ptr()))?;

        // Distinct AppUserModelID so pinned instances group separately.
        let aumid = format!(
            "AppMux.{}.{}",
            crate::paths::sanitize(&inst.app_id),
            crate::paths::sanitize(&inst.name)
        );
        let store: IPropertyStore = link.cast()?;
        let value = PROPVARIANT::from(aumid.as_str());
        store.SetValue(&PKEY_AppUserModel_ID, &value)?;
        store.Commit()?;

        let pf: IPersistFile = link.cast()?;
        let out_w = wide(&out.to_string_lossy());
        pf.Save(PCWSTR(out_w.as_ptr()), true)
            .with_context(|| format!("saving shortcut {}", out.display()))?;
    }
    Ok(out)
}

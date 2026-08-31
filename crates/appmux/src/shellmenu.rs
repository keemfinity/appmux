//! Registry-only cascading context menu (Win10 primary menu, Win11 under
//! "Show more options"). No code ever loads into Explorer: the menu is plain
//! HKCU registry verbs whose commands invoke appmux.exe, so a bug here can
//! never crash the shell.

use crate::store::Db;
use anyhow::Result;
use winreg::enums::HKEY_CURRENT_USER;
use winreg::RegKey;

const CLASSES: &[&str] = &["lnkfile", "exefile"];
const MENU_KEY: &str = "AppMux";
const MAX_ITEMS: usize = 10;

pub fn sync(db: &Db) -> Result<()> {
    // Explorer verbs use the windowless binary so no console ever flashes.
    let exe = std::env::current_exe()?;
    let windowless = exe.with_file_name("appmuxw.exe");
    let exe = if windowless.exists() { windowless } else { exe };
    let exe = exe.to_string_lossy();
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    for class in CLASSES {
        let base_path = format!("Software\\Classes\\{class}\\shell\\{MENU_KEY}");
        // Rebuild from scratch so removed instances disappear.
        let _ = hkcu.delete_subkey_all(&base_path);
        let (base, _) = hkcu.create_subkey(&base_path)?;
        base.set_value("MUIVerb", &"AppMux")?;
        base.set_value("Icon", &format!("\"{exe}\",0"))?;
        base.set_value("SubCommands", &"")?;

        let (shell, _) = hkcu.create_subkey(format!("{base_path}\\shell"))?;

        // "New instance" opens the manager's naming dialog when the manager
        // is installed alongside; otherwise it falls back to auto-naming.
        let manager = std::env::current_exe()?.with_file_name("AppMux.Manager.exe");
        let new_cmd = if manager.exists() {
            format!(
                "\"{}\" new-instance --target \"%1\"",
                manager.to_string_lossy()
            )
        } else {
            format!("\"{exe}\" run --target \"%1\" --new")
        };
        let (new_item, _) = shell.create_subkey("00_new")?;
        new_item.set_value("MUIVerb", &"New instance...")?;
        let (cmd, _) = new_item.create_subkey("command")?;
        cmd.set_value("", &new_cmd)?;

        for (i, name) in db.menu_names(MAX_ITEMS).iter().enumerate() {
            let (item, _) = shell.create_subkey(format!("{:02}_instance", i + 1))?;
            item.set_value("MUIVerb", &format!("Instance: {name}"))?;
            let (cmd, _) = item.create_subkey("command")?;
            cmd.set_value(
                "",
                &format!("\"{exe}\" run --target \"%1\" --instance \"{name}\""),
            )?;
        }
    }
    Ok(())
}

pub fn sync_protocols(db: &Db) -> Result<usize> {
    let current = std::env::current_exe()?;
    let manager = current.with_file_name("AppMux.Manager.exe");
    anyhow::ensure!(
        manager.exists(),
        "AppMux.Manager.exe must be next to appmux.exe to register the protocol router"
    );
    let mut protocols: Vec<String> = db
        .instances
        .iter()
        .flat_map(|instance| instance.protocols.iter())
        .map(|protocol| protocol.to_ascii_lowercase())
        .filter(|protocol| {
            !protocol.is_empty()
                && protocol
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        })
        .collect();
    protocols.sort();
    protocols.dedup();

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let active_classes: std::collections::HashSet<_> = protocols
        .iter()
        .map(|protocol| format!("AppMux.Protocol.{protocol}").to_ascii_lowercase())
        .collect();
    let stale_classes: Vec<_> = hkcu
        .open_subkey(r"Software\Classes")
        .ok()
        .into_iter()
        .flat_map(|classes| {
            classes
                .enum_keys()
                .filter_map(Result::ok)
                .collect::<Vec<_>>()
        })
        .filter(|class| {
            class.to_ascii_lowercase().starts_with("appmux.protocol.")
                && !active_classes.contains(&class.to_ascii_lowercase())
        })
        .collect();
    for class in stale_classes {
        let _ = hkcu.delete_subkey_all(format!(r"Software\Classes\{class}"));
    }
    let capabilities_path = r"Software\AppMux\Capabilities";
    let _ = hkcu.delete_subkey_all(capabilities_path);
    let (capabilities, _) = hkcu.create_subkey(capabilities_path)?;
    capabilities.set_value("ApplicationName", &"AppMux Protocol Router")?;
    capabilities.set_value(
        "ApplicationDescription",
        &"Routes OAuth and deep-link callbacks to a named AppMux instance.",
    )?;
    let (associations, _) = capabilities.create_subkey("URLAssociations")?;
    for protocol in &protocols {
        let prog_id = format!("AppMux.Protocol.{protocol}");
        associations.set_value(protocol, &prog_id)?;
        let class_path = format!(r"Software\Classes\{prog_id}");
        let (class, _) = hkcu.create_subkey(&class_path)?;
        class.set_value("", &format!("URL:{protocol} (AppMux)"))?;
        class.set_value("URL Protocol", &"")?;
        let (icon, _) = class.create_subkey("DefaultIcon")?;
        icon.set_value("", &format!("\"{}\",0", manager.to_string_lossy()))?;
        let (command, _) = class.create_subkey(r"shell\open\command")?;
        command.set_value(
            "",
            &format!("\"{}\" protocol --uri \"%1\"", manager.to_string_lossy()),
        )?;
    }
    let (registered, _) = hkcu.create_subkey(r"Software\RegisteredApplications")?;
    registered.set_value("AppMux Protocol Router", &capabilities_path)?;
    unsafe {
        windows::Win32::UI::Shell::SHChangeNotify(
            windows::Win32::UI::Shell::SHCNE_ASSOCCHANGED,
            windows::Win32::UI::Shell::SHCNF_IDLIST,
            None,
            None,
        );
    }
    Ok(protocols.len())
}

pub fn remove() -> Result<()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    for class in CLASSES {
        let _ = hkcu.delete_subkey_all(format!("Software\\Classes\\{class}\\shell\\{MENU_KEY}"));
    }
    Ok(())
}

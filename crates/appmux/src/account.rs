//! Tier C: real Windows-user isolation through documented APIs.
//! Each instance gets a standard local account, a genuine HKCU hive, and a
//! genuine user profile. Credentials are random and DPAPI-protected for the
//! AppMux owner. No service, injection, ACL takeover, or target modification.

use crate::{launch::LaunchPlan, store::Instance};
use anyhow::{bail, Context, Result};
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL, WAIT_OBJECT_0};
use windows::Win32::NetworkManagement::NetManagement::{
    NERR_UserExists, NetUserAdd, NetUserDel, UF_DONT_EXPIRE_PASSWD, UF_NORMAL_ACCOUNT, UF_SCRIPT,
    USER_ACCOUNT_FLAGS, USER_INFO_1, USER_PRIV_USER,
};
use windows::Win32::Security::Authorization::{
    GetSecurityInfo, SetEntriesInAclW, SetSecurityInfo, EXPLICIT_ACCESS_W, GRANT_ACCESS,
    SE_WINDOW_OBJECT, TRUSTEE_IS_NAME, TRUSTEE_IS_USER,
};
use windows::Win32::Security::Cryptography::{
    BCryptGenRandom, CryptProtectData, CryptUnprotectData, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};
use windows::Win32::Security::{
    LogonUserW, DACL_SECURITY_INFORMATION, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT,
    NO_INHERITANCE,
};
use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, CloseWindowStation, OpenDesktopW, OpenWindowStationW, DESKTOP_CONTROL_FLAGS,
};
use windows::Win32::System::Threading::{
    CreateProcessWithLogonW, GetExitCodeProcess, WaitForSingleObject, CREATE_UNICODE_ENVIRONMENT,
    LOGON_WITH_PROFILE, PROCESS_INFORMATION, STARTUPINFOW,
};
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_WRITE};
use winreg::RegKey;

const CREDENTIAL_FILE: &str = "tier-c.credential";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Stable, local-account-safe identifier (20 chars, Windows' legacy limit).
pub fn account_name(app_id: &str, instance: &str) -> String {
    // FNV-1a is not used for security, only deterministic naming.
    let mut hash = 0xcbf29ce484222325u64;
    for b in format!("{app_id}\0{}", instance.to_ascii_lowercase()).bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("amx_{hash:016x}")
}

fn random_password() -> Result<String> {
    let mut bytes = [0u8; 24];
    let status = unsafe { BCryptGenRandom(None, &mut bytes, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    if status.is_err() {
        bail!("BCryptGenRandom failed: 0x{:08x}", status.0 as u32);
    }
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@$%_-";
    let mut out: String = bytes
        .iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect();
    // Ensure the local password-complexity categories regardless of RNG map.
    out.replace_range(0..4, "Aa1!");
    Ok(out)
}

fn credential_path(inst: &Instance) -> PathBuf {
    inst.data_dir().join(CREDENTIAL_FILE)
}

fn protect(secret: &str) -> Result<Vec<u8>> {
    let mut input = secret.as_bytes().to_vec();
    let input_blob = CRYPT_INTEGER_BLOB {
        cbData: input.len() as u32,
        pbData: input.as_mut_ptr(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptProtectData(
            &input_blob,
            PCWSTR::null(),
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )?;
        let bytes = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(HLOCAL(output.pbData as *mut c_void));
        Ok(bytes)
    }
}

fn unprotect(encrypted: &[u8]) -> Result<String> {
    let mut data = encrypted.to_vec();
    let input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_mut_ptr(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptUnprotectData(
            &input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )?;
        let bytes = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(HLOCAL(output.pbData as *mut c_void));
        String::from_utf8(bytes).context("Tier C credential is not valid UTF-8")
    }
}

unsafe fn grant_window_object(
    handle: HANDLE,
    username: &mut [u16],
    permissions: u32,
) -> Result<()> {
    let mut old_acl = std::ptr::null_mut();
    let mut descriptor = windows::Win32::Security::PSECURITY_DESCRIPTOR::default();
    let status = GetSecurityInfo(
        handle,
        SE_WINDOW_OBJECT,
        DACL_SECURITY_INFORMATION,
        None,
        None,
        Some(&mut old_acl),
        None,
        Some(&mut descriptor),
    );
    anyhow::ensure!(
        status.0 == 0,
        "GetSecurityInfo failed with status {}",
        status.0
    );

    let mut entry = EXPLICIT_ACCESS_W::default();
    entry.grfAccessPermissions = permissions;
    entry.grfAccessMode = GRANT_ACCESS;
    entry.grfInheritance = NO_INHERITANCE;
    entry.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    entry.Trustee.TrusteeType = TRUSTEE_IS_USER;
    entry.Trustee.ptstrName = PWSTR(username.as_mut_ptr());
    let mut new_acl = std::ptr::null_mut();
    let acl_status = SetEntriesInAclW(Some(&[entry]), Some(old_acl), &mut new_acl);
    if acl_status.0 != 0 {
        let _ = LocalFree(HLOCAL(descriptor.0));
        bail!("SetEntriesInAclW failed with status {}", acl_status.0);
    }
    let set_status = SetSecurityInfo(
        handle,
        SE_WINDOW_OBJECT,
        DACL_SECURITY_INFORMATION,
        None,
        None,
        Some(new_acl),
        None,
    );
    let _ = LocalFree(HLOCAL(new_acl as *mut c_void));
    let _ = LocalFree(HLOCAL(descriptor.0));
    anyhow::ensure!(
        set_status.0 == 0,
        "SetSecurityInfo failed with status {}",
        set_status.0
    );
    Ok(())
}

fn grant_interactive_desktop(username: &str) -> Result<()> {
    let mut username_w = wide(username);
    let winsta_w = wide("WinSta0");
    let desktop_w = wide("Default");
    unsafe {
        let winsta =
            OpenWindowStationW(PCWSTR(winsta_w.as_ptr()), false, 0x0002_0000 | 0x0004_0000)?;
        let desktop = OpenDesktopW(
            PCWSTR(desktop_w.as_ptr()),
            DESKTOP_CONTROL_FLAGS(0),
            false,
            0x0002_0000 | 0x0004_0000,
        )?;
        let window_result = grant_window_object(HANDLE(winsta.0), &mut username_w, 0x1000_0000);
        let desktop_result = grant_window_object(HANDLE(desktop.0), &mut username_w, 0x1000_0000);
        let _ = CloseDesktop(desktop);
        let _ = CloseWindowStation(winsta);
        window_result?;
        desktop_result
    }
}

/// Elevated operation. Creates a standard local account, hides its login tile,
/// and stores its random password DPAPI-encrypted. It never touches WindowsApps
/// or target-app ACLs.
pub fn provision(inst: &Instance) -> Result<String> {
    let username = account_name(&inst.app_id, &inst.name);
    let cred = credential_path(inst);
    if cred.exists() {
        grant_interactive_desktop(&username)?;
        return Ok(username);
    }

    let password = random_password()?;
    let mut user_w = wide(&username);
    let mut pass_w = wide(&password);
    let mut comment_w = wide("AppMux isolated instance (managed; do not use interactively)");
    let mut info = USER_INFO_1 {
        usri1_name: PWSTR(user_w.as_mut_ptr()),
        usri1_password: PWSTR(pass_w.as_mut_ptr()),
        usri1_password_age: 0,
        usri1_priv: USER_PRIV_USER,
        usri1_home_dir: PWSTR::null(),
        usri1_comment: PWSTR(comment_w.as_mut_ptr()),
        usri1_flags: USER_ACCOUNT_FLAGS(UF_SCRIPT.0 | UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD.0),
        usri1_script_path: PWSTR::null(),
    };
    let status = unsafe { NetUserAdd(PCWSTR::null(), 1, &mut info as *mut _ as *const u8, None) };
    if status == 5 {
        bail!("Tier C provisioning requires administrator approval. Re-run this command elevated.");
    }
    if status == NERR_UserExists {
        bail!(
            "local account '{username}' already exists but AppMux has no credential for it; \
             refusing to adopt or reset an unknown account"
        );
    }
    if status != 0 {
        bail!("NetUserAdd failed with Windows status {status}");
    }

    let result = (|| -> Result<()> {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let path =
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList";
        let (key, _) = hklm.create_subkey_with_flags(path, KEY_WRITE)?;
        key.set_value(&username, &0u32)?;
        grant_interactive_desktop(&username)?;
        std::fs::create_dir_all(inst.data_dir())?;
        std::fs::write(&cred, protect(&password)?)?;
        // Pre-warm the Windows profile during provisioning so first real launch
        // stays fast. cmd exits immediately after the profile is loaded.
        spawn_with_password(
            &username,
            &password,
            Path::new(r"C:\Windows\System32\cmd.exe"),
            r#""C:\Windows\System32\cmd.exe" /d /c exit"#,
            None,
            false,
            true,
        )?;
        Ok(())
    })();

    if let Err(e) = result {
        unsafe {
            let _ = NetUserDel(PCWSTR::null(), PCWSTR(user_w.as_ptr()));
        }
        let _ = std::fs::remove_file(&cred);
        return Err(e).context("Tier C provisioning rolled back the newly created account");
    }
    Ok(username)
}

fn quote_arg(s: &str) -> String {
    if !s.is_empty() && !s.contains([' ', '\t', '"']) {
        return s.to_string();
    }
    let mut out = String::from("\"");
    let mut slashes = 0;
    for c in s.chars() {
        if c == '\\' {
            slashes += 1;
        } else if c == '"' {
            out.push_str(&"\\".repeat(slashes * 2 + 1));
            out.push('"');
            slashes = 0;
        } else {
            out.push_str(&"\\".repeat(slashes));
            slashes = 0;
            out.push(c);
        }
    }
    out.push_str(&"\\".repeat(slashes * 2));
    out.push('"');
    out
}

fn command_line(plan: &LaunchPlan, data_dir: &Path) -> String {
    let mut parts = vec![quote_arg(&plan.exe.to_string_lossy())];
    if !plan.lnk_args.trim().is_empty() {
        parts.push(plan.lnk_args.trim().to_string());
    }
    let recipe_args: Vec<String> = plan
        .recipe
        .args
        .iter()
        .map(|a| a.replace("{data}", &data_dir.to_string_lossy()))
        .collect();
    let squirrel = plan
        .exe
        .file_name()
        .map(|n| n.eq_ignore_ascii_case("update.exe"))
        .unwrap_or(false)
        && plan
            .lnk_args
            .to_ascii_lowercase()
            .contains("--processstart");
    if squirrel && !recipe_args.is_empty() {
        parts.push("--process-start-args".to_string());
        parts.push(quote_arg(&recipe_args.join(" ")));
    } else {
        parts.extend(recipe_args.iter().map(|a| quote_arg(a)));
    }
    parts.join(" ")
}

fn spawn_with_password(
    username: &str,
    password: &str,
    exe: &Path,
    command: &str,
    cwd: Option<&Path>,
    visible_desktop: bool,
    wait: bool,
) -> Result<u32> {
    let user_w = wide(username);
    let pass_w = wide(password);
    let exe_w = wide(&exe.to_string_lossy());
    let mut command_w = wide(command);
    let domain_w = wide(".");
    let desktop_w = wide(r"winsta0\default");
    let cwd_w = cwd.map(|p| wide(&p.to_string_lossy()));

    let mut token = HANDLE::default();
    unsafe {
        LogonUserW(
            PCWSTR(user_w.as_ptr()),
            PCWSTR(domain_w.as_ptr()),
            PCWSTR(pass_w.as_ptr()),
            LOGON32_LOGON_INTERACTIVE,
            LOGON32_PROVIDER_DEFAULT,
            &mut token,
        )?;
    }

    let mut environment: *mut c_void = std::ptr::null_mut();
    let result = unsafe {
        CreateEnvironmentBlock(&mut environment, token, false)?;
        let mut startup = STARTUPINFOW::default();
        startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        if visible_desktop {
            startup.lpDesktop = PWSTR(desktop_w.as_ptr() as *mut u16);
        }
        let mut process = PROCESS_INFORMATION::default();
        let created = CreateProcessWithLogonW(
            PCWSTR(user_w.as_ptr()),
            PCWSTR(domain_w.as_ptr()),
            PCWSTR(pass_w.as_ptr()),
            LOGON_WITH_PROFILE,
            PCWSTR(exe_w.as_ptr()),
            PWSTR(command_w.as_mut_ptr()),
            CREATE_UNICODE_ENVIRONMENT,
            Some(environment),
            cwd_w
                .as_ref()
                .map(|v| PCWSTR(v.as_ptr()))
                .unwrap_or(PCWSTR::null()),
            &startup,
            &mut process,
        );
        let pid = if created.is_ok() {
            process.dwProcessId
        } else {
            0
        };
        let mut exit_code = None;
        let mut waited = true;
        if created.is_ok() && wait {
            waited = WaitForSingleObject(process.hProcess, 180_000) == WAIT_OBJECT_0;
            if waited {
                let mut code = 0;
                GetExitCodeProcess(process.hProcess, &mut code)?;
                exit_code = Some(code);
            }
        }
        if !process.hThread.is_invalid() {
            let _ = CloseHandle(process.hThread);
        }
        if !process.hProcess.is_invalid() {
            let _ = CloseHandle(process.hProcess);
        }
        let _ = DestroyEnvironmentBlock(environment);
        let _ = CloseHandle(token);
        created?;
        Ok::<(u32, bool, Option<u32>), windows::core::Error>((pid, waited, exit_code))
    }?;
    let (pid, waited, exit_code) = result;
    anyhow::ensure!(waited, "alternate-user process timed out after 180 seconds");
    if let Some(code) = exit_code {
        anyhow::ensure!(code == 0, "alternate-user process exited with code {code}");
    }
    Ok(pid)
}

pub fn data_dir(inst: &Instance) -> Result<PathBuf> {
    let username = inst
        .windows_user
        .as_deref()
        .context("Tier C instance has no Windows account")?;
    let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
    Ok(PathBuf::from(system_drive)
        .join("Users")
        .join(username)
        .join("AppData")
        .join("Local")
        .join("AppMux")
        .join("Instances")
        .join(crate::paths::sanitize(&inst.app_id))
        .join(crate::paths::sanitize(&inst.name)))
}

pub fn launch(inst: &Instance, plan: &LaunchPlan) -> Result<u32> {
    let username = inst
        .windows_user
        .as_deref()
        .context("Tier C instance has no Windows account; provision it first")?;
    let encrypted = std::fs::read(credential_path(inst))
        .context("Tier C credential is missing; provision the instance again")?;
    let password = unprotect(&encrypted)?;
    let command = command_line(plan, &data_dir(inst)?);
    let cwd = plan
        .workdir
        .as_deref()
        .filter(|p| p.exists())
        .or_else(|| plan.exe.parent());
    spawn_with_password(username, &password, &plan.exe, &command, cwd, true, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_account_names_are_safe_and_distinct() {
        assert_eq!(
            account_name("discord", "Work"),
            account_name("discord", "work")
        );
        assert_ne!(
            account_name("discord", "Work"),
            account_name("discord", "Personal")
        );
        assert_eq!(account_name("x", "y").len(), 20);
    }

    #[test]
    fn windows_argument_quoting() {
        assert_eq!(quote_arg("plain"), "plain");
        assert_eq!(quote_arg("has space"), "\"has space\"");
        assert_eq!(quote_arg(r#"a"b"#), r#""a\"b""#);
    }
}

//! Tier C: real Windows-user isolation through documented APIs.
//! Each instance gets a standard local account, a genuine HKCU hive, and a
//! genuine user profile. Credentials are random and DPAPI-protected for the
//! AppMux owner. No service, injection, ACL takeover, or target modification.

use crate::{launch::LaunchPlan, store::Instance};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::ffi::c_void;
use std::io::Read;
use std::path::{Path, PathBuf};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, DuplicateHandle, LocalFree, DUPLICATE_SAME_ACCESS, HANDLE, HLOCAL, WAIT_OBJECT_0,
};
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
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, OpenJobObjectW, TerminateJobObject,
};
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, CloseWindowStation, OpenDesktopW, OpenWindowStationW, DESKTOP_CONTROL_FLAGS,
};
use windows::Win32::System::SystemServices::JOB_OBJECT_TERMINATE;
use windows::Win32::System::Threading::{
    CreateProcessWithLogonW, GetCurrentProcess, GetExitCodeProcess, ResumeThread, TerminateProcess,
    WaitForSingleObject, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, LOGON_WITH_PROFILE,
    PROCESS_INFORMATION, STARTUPINFOW,
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
fn run_profile_initializer(username: &str, password: &str) -> Result<()> {
    let helper = profile_root(username)
        .join("AppData")
        .join("Local")
        .join("AppMux")
        .join("Tools")
        .join("appmux-profile-init.exe");
    std::fs::create_dir_all(
        helper
            .parent()
            .context("profile initializer has no parent")?,
    )?;
    std::fs::copy(std::env::current_exe()?, &helper)?;
    grant_modify(
        helper
            .parent()
            .context("profile initializer has no parent")?,
        username,
    )?;
    let command = format!(
        "{} tier-c init-profile",
        quote_arg(&helper.to_string_lossy())
    );
    spawn_with_password(
        username,
        password,
        &helper,
        &command,
        Some(Path::new(r"C:\Windows\System32")),
        false,
        true,
        None,
    )?;
    Ok(())
}

pub fn provision(inst: &Instance, plan: &LaunchPlan) -> Result<String> {
    let username = account_name(&inst.app_id, &inst.name);
    let cred = credential_path(inst);
    if cred.exists() {
        grant_interactive_desktop(&username)?;
        let password = unprotect(&std::fs::read(&cred)?)?;
        run_profile_initializer(&username, &password)?;
        stage_per_user_app(inst, plan, &username)?;
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
            None,
        )?;
        run_profile_initializer(&username, &password)?;
        stage_per_user_app(inst, plan, &username)?;
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

fn command_line(plan: &LaunchPlan, data_dir: &Path, executable: &Path) -> String {
    let mut parts = vec![quote_arg(&executable.to_string_lossy())];
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

unsafe fn corrected_environment(block: *mut c_void, username: &str) -> Vec<u16> {
    let mut entries = Vec::new();
    let mut drive_entries = Vec::new();
    let mut cursor = block as *const u16;
    loop {
        let mut length = 0usize;
        while *cursor.add(length) != 0 {
            length += 1;
        }
        if length == 0 {
            break;
        }
        let value = String::from_utf16_lossy(std::slice::from_raw_parts(cursor, length));
        if value.starts_with('=') {
            drive_entries.push(value);
        } else if let Some((key, value)) = value.split_once('=') {
            entries.push((key.to_string(), value.to_string()));
        }
        cursor = cursor.add(length + 1);
    }
    let profile = profile_root(username);
    let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
    let replacements = [
        ("USERPROFILE", profile.display().to_string()),
        (
            "APPDATA",
            profile.join(r"AppData\Roaming").display().to_string(),
        ),
        (
            "LOCALAPPDATA",
            profile.join(r"AppData\Local").display().to_string(),
        ),
        (
            "TEMP",
            profile.join(r"AppData\Local\Temp").display().to_string(),
        ),
        (
            "TMP",
            profile.join(r"AppData\Local\Temp").display().to_string(),
        ),
        ("HOMEDRIVE", system_drive),
        ("HOMEPATH", format!(r"\Users\{username}")),
        ("USERNAME", username.to_string()),
    ];
    for (key, value) in replacements {
        if let Some(existing) = entries
            .iter_mut()
            .find(|(name, _)| name.eq_ignore_ascii_case(key))
        {
            existing.1 = value;
        } else {
            entries.push((key.to_string(), value));
        }
    }
    entries.sort_by_key(|(key, _)| key.to_ascii_lowercase());
    let mut output = Vec::new();
    for value in drive_entries {
        output.extend(value.encode_utf16());
        output.push(0);
    }
    for (key, value) in entries {
        output.extend(format!("{key}={value}").encode_utf16());
        output.push(0);
    }
    output.push(0);
    output
}

fn spawn_with_password(
    username: &str,
    password: &str,
    exe: &Path,
    command: &str,
    cwd: Option<&Path>,
    visible_desktop: bool,
    wait: bool,
    job_name: Option<&str>,
) -> Result<u32> {
    let user_w = wide(username);
    let pass_w = wide(password);
    let exe_w = wide(&exe.to_string_lossy());
    let mut command_w = wide(command);
    let domain_w = wide(".");
    let desktop_w = wide(r"winsta0\default");
    let cwd_w = cwd.map(|p| wide(&p.to_string_lossy()));
    let job_w = job_name.map(wide);

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
        let mut corrected_environment = corrected_environment(environment, username);
        let mut startup = STARTUPINFOW::default();
        startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        if visible_desktop {
            startup.lpDesktop = PWSTR(desktop_w.as_ptr() as *mut u16);
        }
        let job = if let Some(name) = &job_w {
            Some(CreateJobObjectW(None, PCWSTR(name.as_ptr()))?)
        } else {
            None
        };
        let flags = if job.is_some() {
            CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED
        } else {
            CREATE_UNICODE_ENVIRONMENT
        };
        let mut process = PROCESS_INFORMATION::default();
        let created = CreateProcessWithLogonW(
            PCWSTR(user_w.as_ptr()),
            PCWSTR(domain_w.as_ptr()),
            PCWSTR(pass_w.as_ptr()),
            LOGON_WITH_PROFILE,
            PCWSTR(exe_w.as_ptr()),
            PWSTR(command_w.as_mut_ptr()),
            flags,
            Some(corrected_environment.as_mut_ptr() as *const c_void),
            cwd_w
                .as_ref()
                .map(|v| PCWSTR(v.as_ptr()))
                .unwrap_or(PCWSTR::null()),
            &startup,
            &mut process,
        );
        let managed = if created.is_ok() {
            if let Some(job) = job {
                let result = (|| -> windows::core::Result<()> {
                    AssignProcessToJobObject(job, process.hProcess)?;
                    let mut remote_job = HANDLE::default();
                    DuplicateHandle(
                        GetCurrentProcess(),
                        job,
                        process.hProcess,
                        &mut remote_job,
                        0,
                        false,
                        DUPLICATE_SAME_ACCESS,
                    )?;
                    if ResumeThread(process.hThread) == u32::MAX {
                        return Err(windows::core::Error::from_win32());
                    }
                    Ok(())
                })();
                let _ = CloseHandle(job);
                result
            } else {
                Ok(())
            }
        } else {
            if let Some(job) = job {
                let _ = CloseHandle(job);
            }
            Ok(())
        };
        if let Err(error) = managed {
            if !process.hProcess.is_invalid() {
                let _ = TerminateProcess(process.hProcess, 1);
            }
            if !process.hThread.is_invalid() {
                let _ = CloseHandle(process.hThread);
            }
            if !process.hProcess.is_invalid() {
                let _ = CloseHandle(process.hProcess);
            }
            let _ = DestroyEnvironmentBlock(environment);
            let _ = CloseHandle(token);
            return Err(error.into());
        }
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
        } else if created.is_ok() && WaitForSingleObject(process.hProcess, 3_000) == WAIT_OBJECT_0 {
            let mut code = 0;
            GetExitCodeProcess(process.hProcess, &mut code)?;
            exit_code = Some(code);
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
    if !wait {
        if let Some(code) = exit_code.filter(|code| *code != 0) {
            bail!("alternate-user process exited during startup with code {code} (0x{code:08X})");
        }
    } else if let Some(code) = exit_code {
        anyhow::ensure!(code == 0, "alternate-user process exited with code {code}");
    }
    Ok(pid)
}

pub fn initialize_known_folders() -> Result<()> {
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{
        FOLDERID_Cookies, FOLDERID_History, FOLDERID_InternetCache, FOLDERID_LocalAppData,
        FOLDERID_LocalAppDataLow, FOLDERID_Profile, FOLDERID_RoamingAppData, SHGetKnownFolderPath,
        KF_FLAG_CREATE,
    };

    for folder in [
        FOLDERID_Profile,
        FOLDERID_RoamingAppData,
        FOLDERID_LocalAppData,
        FOLDERID_LocalAppDataLow,
        FOLDERID_InternetCache,
        FOLDERID_Cookies,
        FOLDERID_History,
    ] {
        unsafe {
            let path = SHGetKnownFolderPath(&folder, KF_FLAG_CREATE, None)?;
            CoTaskMemFree(Some(path.0 as *const c_void));
        }
    }
    Ok(())
}

fn profile_root(username: &str) -> PathBuf {
    let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
    PathBuf::from(format!(r"{system_drive}\"))
        .join("Users")
        .join(username)
}

pub fn data_dir(inst: &Instance) -> Result<PathBuf> {
    let username = inst
        .windows_user
        .as_deref()
        .context("Tier C instance has no Windows account")?;
    Ok(profile_root(username)
        .join("AppData")
        .join("Local")
        .join("AppMux")
        .join("Instances")
        .join(crate::paths::sanitize(&inst.app_id))
        .join(crate::paths::sanitize(&inst.name)))
}

fn owner_profile(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .find(|ancestor| {
            ancestor
                .file_name()
                .is_some_and(|name| name.eq_ignore_ascii_case("AppData"))
        })
        .and_then(Path::parent)
        .map(Path::to_path_buf)
}

fn per_user_install_root(executable: &Path) -> Option<PathBuf> {
    owner_profile(executable)?;
    let parent = executable.parent()?;
    if parent.file_name().is_some_and(|name| {
        name.to_string_lossy()
            .to_ascii_lowercase()
            .starts_with("app-")
    }) {
        parent.parent().map(Path::to_path_buf)
    } else {
        Some(parent.to_path_buf())
    }
}

fn mirrored_install_root(inst: &Instance, source: &Path) -> Result<PathBuf> {
    let username = inst
        .windows_user
        .as_deref()
        .context("Tier C instance has no Windows account")?;
    let owner_profile = owner_profile(source).context("owner profile path is unavailable")?;
    let relative = source
        .strip_prefix(&owner_profile)
        .context("per-user install is outside the owner's Windows profile")?;
    Ok(profile_root(username).join(relative))
}

fn legacy_stage_root(inst: &Instance) -> Result<PathBuf> {
    let username = inst
        .windows_user
        .as_deref()
        .context("Tier C instance has no Windows account")?;
    let program_data = std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into());
    Ok(PathBuf::from(program_data)
        .join("AppMux")
        .join("TierC")
        .join(username)
        .join("Apps")
        .join(crate::paths::sanitize(&inst.app_id)))
}

fn copy_install_tree(source: &Path, destination: &Path) -> Result<()> {
    std::fs::create_dir_all(destination)?;
    let mut app_dirs: Vec<_> = std::fs::read_dir(source)?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false)
                && entry
                    .file_name()
                    .to_string_lossy()
                    .to_ascii_lowercase()
                    .starts_with("app-")
        })
        .map(|entry| entry.file_name())
        .collect();
    app_dirs.sort();
    let newest_app = app_dirs.last().cloned();
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        let lower = name.to_string_lossy().to_ascii_lowercase();
        if lower == "packages" || (lower.starts_with("app-") && newest_app.as_ref() != Some(&name))
        {
            continue;
        }
        let target = destination.join(&name);
        if entry.file_type()?.is_dir() {
            copy_install_tree(&entry.path(), &target)?;
        } else {
            let copy = std::fs::metadata(&target)
                .map(|metadata| metadata.len() != entry.metadata().map(|m| m.len()).unwrap_or(0))
                .unwrap_or(true);
            if copy {
                std::fs::copy(entry.path(), target)?;
            }
        }
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn verify_electron_executable(path: &Path, expected: &str) -> Result<()> {
    anyhow::ensure!(
        expected.len() == 64 && expected.chars().all(|c| c.is_ascii_hexdigit()),
        "invalid Electron executable SHA-256"
    );
    anyhow::ensure!(
        sha256_file(path)?.eq_ignore_ascii_case(expected),
        "Electron executable SHA-256 mismatch: {}",
        path.display()
    );
    Ok(())
}

fn ensure_electron_host(
    version: &str,
    expected_archive_sha256: &str,
    expected_executable_sha256: &str,
) -> Result<PathBuf> {
    anyhow::ensure!(
        version.chars().all(|c| c.is_ascii_digit() || c == '.')
            && expected_archive_sha256.len() == 64
            && expected_archive_sha256
                .chars()
                .all(|c| c.is_ascii_hexdigit()),
        "invalid Electron host version or SHA-256"
    );
    let tool = crate::paths::root()
        .join("Tools")
        .join(format!("Electron-{version}"));
    let destination = tool.join("dist");
    if destination.join("electron.exe").exists() {
        verify_electron_executable(
            &destination.join("electron.exe"),
            expected_executable_sha256,
        )?;
        return Ok(destination);
    }
    let npm_source = tool.join("node_modules").join("electron").join("dist");
    if npm_source.join("electron.exe").exists() {
        verify_electron_executable(&npm_source.join("electron.exe"), expected_executable_sha256)?;
        copy_install_tree(&npm_source, &destination)?;
        verify_electron_executable(
            &destination.join("electron.exe"),
            expected_executable_sha256,
        )?;
        return Ok(destination);
    }
    std::fs::create_dir_all(&tool)?;
    let script = crate::paths::root().join("install-electron-host.ps1");
    std::fs::write(
        &script,
        r#"param([string]$Version,[string]$ExpectedSha256,[string]$Destination)
$ErrorActionPreference='Stop'
$zip=Join-Path ([IO.Path]::GetTempPath()) "electron-v$Version-win32-x64.zip"
$url="https://github.com/electron/electron/releases/download/v$Version/electron-v$Version-win32-x64.zip"
Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zip
$actual=(Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
if($actual -ne $ExpectedSha256){Remove-Item -LiteralPath $zip -Force;throw "Electron archive SHA-256 mismatch"}
if(Test-Path -LiteralPath $Destination){Remove-Item -LiteralPath $Destination -Recurse -Force}
Expand-Archive -LiteralPath $zip -DestinationPath $Destination -Force
Remove-Item -LiteralPath $zip -Force
if(-not (Test-Path -LiteralPath (Join-Path $Destination 'electron.exe'))){throw 'Electron archive did not contain electron.exe'}
"#,
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
        .arg("-Version")
        .arg(version)
        .arg("-ExpectedSha256")
        .arg(expected_archive_sha256)
        .arg("-Destination")
        .arg(&destination)
        .output()?;
    let _ = std::fs::remove_file(&script);
    if !output.status.success() {
        bail!(
            "installing verified Electron host failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    verify_electron_executable(
        &destination.join("electron.exe"),
        expected_executable_sha256,
    )?;
    Ok(destination)
}

fn grant_modify(path: &Path, username: &str) -> Result<()> {
    let grant = format!("{username}:(OI)(CI)M");
    let output = std::process::Command::new("icacls.exe")
        .arg(path)
        .args(["/grant", &grant, "/T", "/C", "/Q"])
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "granting isolated account access to {} failed: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

pub fn stage_per_user_app(inst: &Instance, plan: &LaunchPlan, username: &str) -> Result<()> {
    let source = per_user_install_root(&plan.exe);
    let Some(source) = source else {
        return Ok(());
    };
    let mut staged = inst.clone();
    staged.windows_user = Some(username.to_string());
    let destination = mirrored_install_root(&staged, &source)?;
    copy_install_tree(&source, &destination).with_context(|| {
        format!(
            "mirroring per-user application {} into isolated Windows profile",
            source.display()
        )
    })?;
    grant_modify(&destination, username)?;
    if let Some(version) = plan.recipe.tier_c_electron_host.as_deref() {
        let archive_sha256 = plan
            .recipe
            .tier_c_electron_sha256
            .as_deref()
            .context("alternate Electron host has no trusted archive SHA-256")?;
        let executable_sha256 = plan
            .recipe
            .tier_c_electron_exe_sha256
            .as_deref()
            .context("alternate Electron host has no trusted executable SHA-256")?;
        let host_source = ensure_electron_host(version, archive_sha256, executable_sha256)?;
        let host_destination = profile_root(username)
            .join("AppData")
            .join("Local")
            .join("AppMux")
            .join("Tools")
            .join(format!("Electron-{version}"));
        copy_install_tree(&host_source, &host_destination)?;
        verify_electron_executable(&host_destination.join("electron.exe"), executable_sha256)?;
        grant_modify(&host_destination, username)?;
    }
    if let Some(name) = plan.recipe.tier_c_user_data_dir.as_deref() {
        anyhow::ensure!(
            Path::new(name).file_name() == Some(std::ffi::OsStr::new(name)),
            "Tier C user-data directory must be one safe path component"
        );
        let user_data = profile_root(username)
            .join("AppData")
            .join("Roaming")
            .join(name);
        std::fs::create_dir_all(user_data.join("logs"))?;
        grant_modify(&user_data, username)?;
    }
    Ok(())
}

pub fn remove(inst: &Instance) -> Result<()> {
    let username = inst
        .windows_user
        .as_deref()
        .context("Tier C instance has no Windows account")?;
    anyhow::ensure!(
        username == account_name(&inst.app_id, &inst.name),
        "refusing to remove an account that does not match this AppMux instance"
    );
    let job_name = format!(r"Local\AppMux.TierC.{username}");
    let job_w = wide(&job_name);
    if let Ok(job) = unsafe { OpenJobObjectW(JOB_OBJECT_TERMINATE, false, PCWSTR(job_w.as_ptr())) }
    {
        unsafe {
            let _ = TerminateJobObject(job, 0);
            let _ = CloseHandle(job);
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    let script = crate::paths::root().join("tier-c-remove.ps1");
    std::fs::write(
        &script,
        r#"param([string]$Username,[string]$Staging)
$ErrorActionPreference='Stop'
$user=Get-LocalUser -Name $Username -ErrorAction SilentlyContinue
if($user){
  if($user.Description -ne 'AppMux isolated instance (managed; do not use interactively)'){throw 'Account is not AppMux-managed'}
  $profile=Get-CimInstance Win32_UserProfile | Where-Object SID -eq $user.SID.Value
  if($profile){
    if($profile.Loaded){throw 'The isolated profile is still in use; close its applications and retry'}
    if((Split-Path $profile.LocalPath -Leaf) -ne $Username){throw 'Unexpected isolated profile path'}
    $profile | Remove-CimInstance
  }
  Remove-LocalUser -Name $Username
}
& reg.exe delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList' /v $Username /f 2>$null | Out-Null
if(Test-Path -LiteralPath $Staging){Remove-Item -LiteralPath $Staging -Recurse -Force}
"#,
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
        .arg("-Username")
        .arg(username)
        .arg("-Staging")
        .arg(legacy_stage_root(inst)?)
        .output()?;
    let _ = std::fs::remove_file(&script);
    if !output.status.success() {
        bail!(
            "removing Tier C account failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let _ = std::fs::remove_file(credential_path(inst));
    Ok(())
}

fn staged_executable(inst: &Instance, plan: &LaunchPlan) -> Result<Option<PathBuf>> {
    let Some(source) = per_user_install_root(&plan.exe) else {
        return Ok(None);
    };
    let relative = plan.exe.strip_prefix(&source)?;
    let root = mirrored_install_root(inst, &source)?;
    let mut candidate = root.join(relative);
    let mut versions: Vec<_> = std::fs::read_dir(&source)?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false)
                && entry
                    .file_name()
                    .to_string_lossy()
                    .to_ascii_lowercase()
                    .starts_with("app-")
        })
        .map(|entry| entry.file_name())
        .collect();
    versions.sort();
    if let Some(name) = plan.recipe.tier_c_electron_app.as_deref() {
        anyhow::ensure!(
            Path::new(name).file_name() == Some(std::ffi::OsStr::new(name)),
            "alternate Electron app executable must be one safe path component"
        );
        let version = versions
            .last()
            .context("alternate Electron app has no staged version directory")?;
        candidate = root.join(version).join(name);
    } else if plan.exe.parent() == Some(source.as_path())
        && !plan
            .exe
            .file_name()
            .is_some_and(|name| name.eq_ignore_ascii_case("update.exe"))
    {
        if let (Some(version), Some(name)) = (versions.last(), plan.exe.file_name()) {
            candidate = root.join(version).join(name);
        }
    }
    Ok(Some(candidate))
}

fn stop_image(inst: &Instance, image: &str) -> Result<()> {
    let username = inst
        .windows_user
        .as_deref()
        .context("Tier C instance has no Windows account; provision it first")?;
    let encrypted = std::fs::read(credential_path(inst))
        .context("Tier C credential is missing; provision the instance again")?;
    let password = unprotect(&encrypted)?;
    anyhow::ensure!(
        !image.is_empty()
            && image
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')),
        "invalid process image name"
    );
    let executable = Path::new(r"C:\Windows\System32\cmd.exe");
    let command = format!(
        r#""C:\Windows\System32\cmd.exe" /d /c "taskkill /f /t /im {} >nul 2>&1 & exit /b 0""#,
        image
    );
    spawn_with_password(
        username,
        &password,
        executable,
        &command,
        Some(Path::new(r"C:\Windows\System32")),
        false,
        true,
        None,
    )?;
    Ok(())
}

pub fn stop(inst: &Instance, plan: &LaunchPlan) -> Result<()> {
    let job_name = format!(
        r"Local\AppMux.TierC.{}",
        account_name(&inst.app_id, &inst.name)
    );
    let job_w = wide(&job_name);
    if let Ok(job) = unsafe { OpenJobObjectW(JOB_OBJECT_TERMINATE, false, PCWSTR(job_w.as_ptr())) }
    {
        let result = unsafe { TerminateJobObject(job, 0) };
        unsafe {
            let _ = CloseHandle(job);
        }
        result?;
        std::thread::sleep(std::time::Duration::from_secs(2));
        return Ok(());
    }
    anyhow::ensure!(
        plan.recipe.tier_c_electron_host.is_none(),
        "isolated instance job is not available; relaunch the instance before stopping it"
    );
    let image = plan
        .exe
        .file_name()
        .context("target has no executable file name")?
        .to_string_lossy()
        .to_string();
    stop_image(inst, &image)
}

pub fn launch(inst: &Instance, plan: &LaunchPlan) -> Result<u32> {
    let username = inst
        .windows_user
        .as_deref()
        .context("Tier C instance has no Windows account; provision it first")?;
    let encrypted = std::fs::read(credential_path(inst))
        .context("Tier C credential is missing; provision the instance again")?;
    let password = unprotect(&encrypted)?;
    let staged = staged_executable(inst, plan)?;
    let (executable, command) = if let Some(version) = plan.recipe.tier_c_electron_host.as_deref() {
        let host = profile_root(username)
            .join("AppData")
            .join("Local")
            .join("AppMux")
            .join("Tools")
            .join(format!("Electron-{version}"))
            .join("electron.exe");
        let app = staged
            .as_deref()
            .and_then(Path::parent)
            .context("mirrored Electron application has no parent directory")?
            .join("resources")
            .join("app.asar");
        let command = format!(
            "{} {} --resourcePath={}",
            quote_arg(&host.to_string_lossy()),
            quote_arg(&app.to_string_lossy()),
            quote_arg(&app.to_string_lossy())
        );
        (host, command)
    } else {
        let executable = staged.clone().unwrap_or_else(|| plan.exe.clone());
        let command = command_line(plan, &data_dir(inst)?, &executable);
        (executable, command)
    };
    let cwd = if staged.is_some() {
        Some(Path::new(r"C:\Windows\System32"))
    } else {
        plan.workdir
            .as_deref()
            .filter(|p| p.exists())
            .or_else(|| plan.exe.parent())
    };
    let job = format!(
        r"Local\AppMux.TierC.{}",
        account_name(&inst.app_id, &inst.name)
    );
    spawn_with_password(
        username,
        &password,
        &executable,
        &command,
        cwd,
        true,
        false,
        Some(&job),
    )
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
    fn tier_c_profile_root_is_absolute() {
        assert!(profile_root("test-account").is_absolute());
        assert!(profile_root("test-account").ends_with(r"Users\test-account"));
    }

    #[test]
    fn windows_argument_quoting() {
        assert_eq!(quote_arg("plain"), "plain");
        assert_eq!(quote_arg("has space"), "\"has space\"");
        assert_eq!(quote_arg(r#"a"b"#), r#""a\"b""#);
    }
}

//! Tier C: real Windows-user isolation through documented APIs.
//! Each instance gets a standard local account, a genuine HKCU hive, and a
//! genuine user profile. Credentials are random and DPAPI-protected for the
//! AppMux owner. No service, injection, ACL takeover, or target modification.

use crate::{launch::LaunchPlan, store::Instance};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::ffi::c_void;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, DuplicateHandle, LocalFree, BOOL, DUPLICATE_SAME_ACCESS, E_ACCESSDENIED, HANDLE,
    HLOCAL, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::NetworkManagement::NetManagement::{
    NERR_UserExists, NetUserAdd, NetUserDel, UF_DONT_EXPIRE_PASSWD, UF_NORMAL_ACCOUNT, UF_SCRIPT,
    USER_ACCOUNT_FLAGS, USER_INFO_1, USER_PRIV_USER,
};
use windows::Win32::Security::Authorization::{
    GetSecurityInfo, SetEntriesInAclW, SetSecurityInfo, EXPLICIT_ACCESS_W, GRANT_ACCESS,
    SE_KERNEL_OBJECT, SE_OBJECT_TYPE, SE_WINDOW_OBJECT, TRUSTEE_IS_NAME, TRUSTEE_IS_USER,
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
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob,
    JobObjectAssociateCompletionPortInformation, JobObjectBasicAccountingInformation,
    JobObjectExtendedLimitInformation, OpenJobObjectW, QueryInformationJobObject,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_ASSOCIATE_COMPLETION_PORT,
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, CloseWindowStation, OpenDesktopW, OpenWindowStationW, DESKTOP_CONTROL_FLAGS,
};
use windows::Win32::System::SystemServices::{
    JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO, JOB_OBJECT_QUERY, JOB_OBJECT_TERMINATE,
};
use windows::Win32::System::Threading::{
    CreateEventW, CreateProcessWithLogonW, GetCurrentProcess, GetExitCodeProcess, OpenEventW,
    OpenProcess, QueryFullProcessImageNameW, ResumeThread, SetEvent, TerminateProcess,
    WaitForSingleObject, CREATE_BREAKAWAY_FROM_JOB, CREATE_NO_WINDOW, CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT, EVENT_MODIFY_STATE, LOGON_WITH_PROFILE, PROCESS_INFORMATION,
    PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, STARTUPINFOW,
};
use windows::Win32::System::IO::{CreateIoCompletionPort, GetQueuedCompletionStatus};
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_WRITE};
use winreg::RegKey;

const CREDENTIAL_FILE: &str = "tier-c.credential";
const SLACK_451191_EXE_SHA256: &str =
    "aa45421e2f80d72402169eb3a81b740b045422c8968edd0cbdadcdf35bd2f170";
const SLACK_451191_ASAR_SHA256: &str =
    "4dabfcddd110a9be9d9e1725d8b6e87825c25ee3744f7b013a1ce7536aaf717e";
const ELECTRON_FUSE_SENTINEL: &[u8] = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX";
const SLACK_451191_FUSES: &[u8] = b"\x01\x09010011001";
const SLACK_451191_PATCHED_FUSES: &[u8] = b"\x01\x09010001001";
const SLACK_451191_SINGLETON: &[u8] = b"l.app.requestSingleInstanceLock((0,o._K)())";
const SLACK_451191_OPEN_EXTERNAL: &[u8] = b"oe.shell.openExternal";
const SLACK_451191_APPMUX_OPEN_EXTERNAL: &[u8] = b"global.appmuxOpen    ";
const SLACK_451191_OPEN_EXTERNAL_SELECTOR: &[u8] = b"const I=n?Vp:y_";
const SLACK_451191_APPMUX_SELECTOR: &[u8] = b"const I=Vp     ";
const FIGMA_126816_EXE_SHA256: &str =
    "da8e4949e1ec02c025e5ca51d4f7c073863a655fe1d131bf5074bc56534b9682";
const FIGMA_126816_ASAR_SHA256: &str =
    "d340b3555733fd9b0e35cd75c3f47077cc901c8704f2f59bcbb2cc0b53efd520";
const FIGMA_126816_PATCHED_ASAR_SHA256: &str =
    "ba7e8e4624a2de6e707a771fabc25cd1d205146db850f8f4c60b270659c1b763";
const FIGMA_126816_BINDINGS_SHA256: &str =
    "c7b6ea2b6aadd778d1df22a150a89c2961825ed84ed117818ef2dcd86c1c8668";
const FIGMA_126816_DESKTOP_RUST_SHA256: &str =
    "fc254dbfa7652694fc93a687375501452d84d26020fc77c2a109055f0eb6564a";
const FIGMA_126816_AGENT_SHA256: &str =
    "39f63268eb5170e7378886636d441da9af1a2203cd6d88db01df15917de0065f";
const FIGMA_126816_SINGLETON: &[u8] = b"Ut.app.requestSingleInstanceLock(t)";
const FIGMA_126816_UPDATE_GATE: &[u8] = b"await n5e()";
const FIGMA_126816_APPDATA: &[u8] = b"pi.join(zl.app.getPath(\"appData\"),\"Figma\")";
const FIGMA_ELECTRON_VERSION: &str = "42.9.2";
const FIGMA_ELECTRON_ARCHIVE_SHA256: &str =
    "9670d8133cba62f9bfa0e29f86410c42649cb16b2e7b273b1b8fed1fa6bb4db9";
const FIGMA_ELECTRON_EXE_SHA256: &str =
    "01cabca68ca51a8a1d88d7a8f879273b9e2b7007ba614c07daa5fb8b0d6546de";
const MAX_DEFERRED_PROTOCOL_URI_LEN: usize = 8192;
const DEFERRED_PROTOCOL_WAIT_MS: u32 = 30_000;

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

fn stop_event_name(inst: &Instance) -> String {
    format!(
        r"Local\AppMux.StopEvent.v1.{}",
        account_name(&inst.app_id, &inst.name)
    )
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

unsafe fn grant_object(
    handle: HANDLE,
    object_type: SE_OBJECT_TYPE,
    username: &mut [u16],
    permissions: u32,
) -> Result<()> {
    let mut old_acl = std::ptr::null_mut();
    let mut descriptor = windows::Win32::Security::PSECURITY_DESCRIPTOR::default();
    let status = GetSecurityInfo(
        handle,
        object_type,
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
        object_type,
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
        let window_result = grant_object(
            HANDLE(winsta.0),
            SE_WINDOW_OBJECT,
            &mut username_w,
            0x1000_0000,
        );
        let desktop_result = grant_object(
            HANDLE(desktop.0),
            SE_WINDOW_OBJECT,
            &mut username_w,
            0x1000_0000,
        );
        let _ = CloseDesktop(desktop);
        let _ = CloseWindowStation(winsta);
        window_result?;
        desktop_result
    }
}

fn grant_job_access(handle: HANDLE, username: &str) -> Result<()> {
    let mut username_w = wide(username);
    unsafe { grant_object(handle, SE_KERNEL_OBJECT, &mut username_w, 0x001f_001f) }
}

fn run_profile_initializer(
    inst: &Instance,
    plan: &LaunchPlan,
    username: &str,
    password: &str,
) -> Result<()> {
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
    let mut command = format!(
        "{} tier-c init-profile",
        quote_arg(&helper.to_string_lossy())
    );
    if plan.recipe.tier_d_patch.is_some() {
        let mut stored = inst.clone();
        stored.windows_user = Some(username.to_string());
        let config = electron_host_config(&stored, plan, username)?;
        let protocol = plan
            .recipe
            .tier_c_protocol
            .as_deref()
            .context("Tier D app has no callback protocol")?;
        let public = std::env::var_os("PUBLIC")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Users\Public"));
        let status = public
            .join("Documents")
            .join(format!("AppMux-Auth-{username}.json"));
        command.push_str(&format!(
            " --protocol {} --helper {} --host {} --hosted-app {} --shim-target {} --profile {} --auth-app {} --status {} --icon {} --app-user-model-id {}",
            quote_arg(protocol),
            quote_arg(&config.helper.to_string_lossy()),
            quote_arg(&config.host.to_string_lossy()),
            quote_arg(&config.shim_app.to_string_lossy()),
            quote_arg(&config.app.to_string_lossy()),
            quote_arg(&config.user_data.to_string_lossy()),
            quote_arg(&config.auth_app.to_string_lossy()),
            quote_arg(&status.to_string_lossy()),
            quote_arg(&config.icon.to_string_lossy()),
            quote_arg(&config.app_user_model_id)
        ));
    }
    spawn_with_password(
        username,
        password,
        &helper,
        &command,
        Some(Path::new(r"C:\Windows\System32")),
        false,
        true,
        None,
        false,
    )?;
    Ok(())
}

/// Elevated operation. Creates a standard local account, hides its login tile,
/// and stores its random password DPAPI-encrypted. It never touches WindowsApps
/// or target-app ACLs.
pub fn provision(inst: &Instance, plan: &LaunchPlan) -> Result<String> {
    let username = account_name(&inst.app_id, &inst.name);
    let cred = credential_path(inst);
    if cred.exists() {
        grant_interactive_desktop(&username)?;
        let password = unprotect(&std::fs::read(&cred)?)?;
        stage_per_user_app(inst, plan, &username)?;
        run_profile_initializer(inst, plan, &username, &password)?;
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
            false,
        )?;
        stage_per_user_app(inst, plan, &username)?;
        run_profile_initializer(inst, plan, &username, &password)?;
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

#[derive(Clone, Copy, Debug)]
struct ElectronHostCommandConfig<'a> {
    helper: &'a Path,
    host: &'a Path,
    hosted_app: &'a Path,
    shim_target: &'a Path,
    profile: &'a Path,
    auth_app: &'a Path,
    status: &'a Path,
    icon: &'a Path,
    app_user_model_id: &'a str,
}

#[derive(Clone, Copy, Default)]
struct ProfileInitializationOptions<'a> {
    protocol: Option<&'a str>,
    helper: Option<&'a Path>,
    host: Option<&'a Path>,
    hosted_app: Option<&'a Path>,
    shim_target: Option<&'a Path>,
    profile: Option<&'a Path>,
    auth_app: Option<&'a Path>,
    status: Option<&'a Path>,
    icon: Option<&'a Path>,
    app_user_model_id: Option<&'a str>,
}

fn complete_profile_initialization<'a>(
    options: ProfileInitializationOptions<'a>,
) -> Result<Option<(&'a str, ElectronHostCommandConfig<'a>)>> {
    let missing: Vec<_> = [
        ("protocol", options.protocol.is_none()),
        ("helper", options.helper.is_none()),
        ("host", options.host.is_none()),
        ("hosted-app", options.hosted_app.is_none()),
        ("shim-target", options.shim_target.is_none()),
        ("profile", options.profile.is_none()),
        ("auth-app", options.auth_app.is_none()),
        ("status", options.status.is_none()),
        ("icon", options.icon.is_none()),
        ("app-user-model-id", options.app_user_model_id.is_none()),
    ]
    .into_iter()
    .filter_map(|(name, is_missing)| is_missing.then_some(name))
    .collect();
    if missing.len() == 10 {
        return Ok(None);
    }
    anyhow::ensure!(
        missing.is_empty(),
        "incomplete Tier D profile configuration; missing: {}",
        missing.join(", ")
    );
    Ok(Some((
        options.protocol.expect("validated protocol"),
        ElectronHostCommandConfig {
            helper: options.helper.expect("validated helper"),
            host: options.host.expect("validated host"),
            hosted_app: options.hosted_app.expect("validated hosted app"),
            shim_target: options.shim_target.expect("validated shim target"),
            profile: options.profile.expect("validated profile"),
            auth_app: options.auth_app.expect("validated auth app"),
            status: options.status.expect("validated status"),
            icon: options.icon.expect("validated icon"),
            app_user_model_id: options
                .app_user_model_id
                .expect("validated app user model id"),
        },
    )))
}

fn path_is_within_profile(user_profile: &Path, path: &Path) -> bool {
    user_profile.is_absolute()
        && path.is_absolute()
        && path.strip_prefix(user_profile).is_ok_and(|relative| {
            !relative.as_os_str().is_empty()
                && relative
                    .components()
                    .all(|component| matches!(component, std::path::Component::Normal(_)))
        })
}

fn validate_profile_protocol_config(
    protocol: &str,
    user_profile: &Path,
    public_profile: &Path,
    config: ElectronHostCommandConfig<'_>,
) -> Result<()> {
    anyhow::ensure!(protocol == "slack", "unsupported Tier D protocol");
    anyhow::ensure!(
        config.app_user_model_id.starts_with("AppMux.")
            && config
                .app_user_model_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')),
        "invalid Tier D AppUserModelID"
    );
    let hidden_paths = [
        config.helper,
        config.host,
        config.hosted_app,
        config.shim_target,
        config.profile,
        config.auth_app,
        config.icon,
    ];
    anyhow::ensure!(
        hidden_paths
            .into_iter()
            .all(|path| path_is_within_profile(user_profile, path)),
        "Tier D authentication file is outside the isolated profile"
    );
    let username = user_profile
        .file_name()
        .context("Tier D profile has no account name")?;
    let expected_status = public_profile
        .join("Documents")
        .join(format!("AppMux-Auth-{}.json", username.to_string_lossy()));
    anyhow::ensure!(
        config.status == expected_status,
        "Tier D authentication status path is not the expected public handoff file"
    );
    Ok(())
}

fn validate_callback_uri(uri: &str) -> Result<()> {
    anyhow::ensure!(
        !uri.is_empty() && uri.len() <= MAX_DEFERRED_PROTOCOL_URI_LEN,
        "callback URI has an invalid length"
    );
    anyhow::ensure!(
        !uri.chars().any(char::is_control),
        "callback URI contains control characters"
    );
    let payload = uri
        .strip_prefix("slack:")
        .context("unsupported callback URI scheme")?;
    anyhow::ensure!(!payload.is_empty(), "callback URI has no payload");
    Ok(())
}

fn validate_wait_pid(wait_pid: u32, current_pid: u32) -> Result<()> {
    anyhow::ensure!(
        wait_pid != 0 && wait_pid != current_pid,
        "invalid deferred host wait PID"
    );
    Ok(())
}

fn read_callback_uri(reader: &mut impl Read) -> Result<String> {
    let mut bytes = Vec::with_capacity(MAX_DEFERRED_PROTOCOL_URI_LEN + 1);
    reader
        .take((MAX_DEFERRED_PROTOCOL_URI_LEN + 1) as u64)
        .read_to_end(&mut bytes)
        .context("reading the callback URI from stdin")?;
    anyhow::ensure!(
        bytes.len() <= MAX_DEFERRED_PROTOCOL_URI_LEN,
        "callback URI exceeds the maximum length"
    );
    let uri = String::from_utf8(bytes).context("callback URI from stdin is not valid UTF-8")?;
    validate_callback_uri(&uri)?;
    Ok(uri)
}

#[derive(Clone, Copy, Debug)]
struct DeferredHostElectronPlan<'a> {
    wait_pid: u32,
    helper: &'a Path,
    host: &'a Path,
    hosted_app: &'a Path,
    shim_target: &'a Path,
    profile: &'a Path,
    auth_app: &'a Path,
    status: &'a Path,
    icon: &'a Path,
    app_user_model_id: &'a str,
    job_name: Option<&'a str>,
}

fn validate_deferred_host_plan(
    plan: DeferredHostElectronPlan<'_>,
    current_pid: u32,
    user_profile: &Path,
    public_profile: &Path,
) -> Result<()> {
    validate_wait_pid(plan.wait_pid, current_pid)?;
    validate_profile_protocol_config(
        "slack",
        user_profile,
        public_profile,
        ElectronHostCommandConfig {
            helper: plan.helper,
            host: plan.host,
            hosted_app: plan.hosted_app,
            shim_target: plan.shim_target,
            profile: plan.profile,
            auth_app: plan.auth_app,
            status: plan.status,
            icon: plan.icon,
            app_user_model_id: plan.app_user_model_id,
        },
    )?;
    if let Some(name) = plan.job_name {
        anyhow::ensure!(
            name.starts_with(r"Local\AppMux.TierC.")
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '\\')),
            "invalid deferred host job name"
        );
    }
    Ok(())
}

fn validate_deferred_host_paths(
    plan: DeferredHostElectronPlan<'_>,
    user_profile: &Path,
) -> Result<()> {
    let canonical_profile = std::fs::canonicalize(user_profile)
        .context("resolving the deferred host USERPROFILE path")?;
    for path in [
        plan.helper,
        plan.host,
        plan.hosted_app,
        plan.shim_target,
        plan.profile,
        plan.auth_app,
        plan.icon,
    ] {
        let canonical = std::fs::canonicalize(path)
            .with_context(|| format!("resolving deferred host path {}", path.display()))?;
        anyhow::ensure!(
            canonical.starts_with(&canonical_profile),
            "deferred host path resolves outside the isolated profile"
        );
    }
    Ok(())
}

fn wait_for_auth_process(wait_pid: u32) -> Result<()> {
    let process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, wait_pid) }
        .context("OpenProcess failed for the authentication process")?;
    let wait_result = unsafe { WaitForSingleObject(process, DEFERRED_PROTOCOL_WAIT_MS) };
    let wait_error = (wait_result != WAIT_OBJECT_0 && wait_result != WAIT_TIMEOUT)
        .then(windows::core::Error::from_win32);
    unsafe {
        let _ = CloseHandle(process);
    }
    anyhow::ensure!(
        wait_result != WAIT_TIMEOUT,
        "authentication process did not exit before the deferred host timeout"
    );
    if let Some(error) = wait_error {
        return Err(error).context("WaitForSingleObject failed for the authentication process");
    }
    Ok(())
}

struct PreparedDeferredHostLaunch<'a> {
    plan: DeferredHostElectronPlan<'a>,
    uri: String,
}

fn prepare_deferred_host_launch<'a>(
    reader: &mut impl Read,
    plan: DeferredHostElectronPlan<'a>,
    current_pid: u32,
    user_profile: &Path,
    public_profile: &Path,
) -> Result<PreparedDeferredHostLaunch<'a>> {
    validate_deferred_host_plan(plan, current_pid, user_profile, public_profile)?;
    let uri = read_callback_uri(reader)?;
    Ok(PreparedDeferredHostLaunch { plan, uri })
}

fn launch_prepared_deferred_host(
    prepared: &PreparedDeferredHostLaunch<'_>,
    launch: impl FnOnce(DeferredHostElectronPlan<'_>, &str) -> Result<()>,
) -> Result<()> {
    launch(prepared.plan, &prepared.uri)
}

#[allow(clippy::too_many_arguments)]
pub fn defer_host_electron(
    wait_pid: u32,
    host: &Path,
    hosted_app: &Path,
    shim_target: &Path,
    profile: &Path,
    auth_app: &Path,
    status: &Path,
    icon: &Path,
    app_user_model_id: &str,
    job_name: Option<&str>,
) -> Result<()> {
    let helper = std::env::current_exe().context("deferred host helper path is unavailable")?;
    let user_profile = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .context("deferred host has no USERPROFILE")?;
    let public_profile = std::env::var_os("PUBLIC")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Users\Public"));
    let plan = DeferredHostElectronPlan {
        wait_pid,
        helper: &helper,
        host,
        hosted_app,
        shim_target,
        profile,
        auth_app,
        status,
        icon,
        app_user_model_id,
        job_name,
    };
    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();
    let prepared = prepare_deferred_host_launch(
        &mut stdin,
        plan,
        std::process::id(),
        &user_profile,
        &public_profile,
    )?;
    validate_deferred_host_paths(prepared.plan, &user_profile)?;
    wait_for_auth_process(prepared.plan.wait_pid)?;
    launch_prepared_deferred_host(&prepared, |plan, uri| {
        host_electron(
            plan.host,
            plan.hosted_app,
            Some(plan.shim_target),
            Some(plan.profile),
            Some(plan.auth_app),
            Some(plan.status),
            plan.icon,
            plan.app_user_model_id,
            plan.job_name,
            Some(uri),
        )
    })
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

fn configure_broker_job(job: HANDLE) -> Result<HANDLE> {
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &limits as *const _ as *const c_void,
            std::mem::size_of_val(&limits) as u32,
        )
        .context("setting Job Object broker limits")?;
    }
    let completion = unsafe {
        CreateIoCompletionPort(INVALID_HANDLE_VALUE, None, 0, 1)
            .context("creating the Job Object completion port")?
    };
    let association = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
        CompletionKey: job.0,
        CompletionPort: completion,
    };
    if let Err(error) = unsafe {
        SetInformationJobObject(
            job,
            JobObjectAssociateCompletionPortInformation,
            &association as *const _ as *const c_void,
            std::mem::size_of_val(&association) as u32,
        )
    } {
        unsafe {
            let _ = CloseHandle(completion);
        }
        return Err(error).context("associating the Job Object completion port");
    }
    Ok(completion)
}

fn wait_for_job_to_empty(job: HANDLE, completion: HANDLE, stop_event: HANDLE) -> Result<()> {
    let mut stopping = false;
    loop {
        if !stopping && unsafe { WaitForSingleObject(stop_event, 0) } == WAIT_OBJECT_0 {
            unsafe {
                TerminateJobObject(job, 0)?;
            }
            stopping = true;
        }
        let mut message = 0u32;
        let mut key = 0usize;
        let mut overlapped = std::ptr::null_mut();
        match unsafe {
            GetQueuedCompletionStatus(completion, &mut message, &mut key, &mut overlapped, 1000)
        } {
            Ok(()) if key == job.0 as usize && message == JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO => {
                return Ok(())
            }
            Ok(()) => continue,
            Err(error) if error.code().0 as u32 == 0x8007_0102 => {}
            Err(error) => return Err(error).context("waiting for Job Object completion"),
        }
        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        unsafe {
            QueryInformationJobObject(
                job,
                JobObjectBasicAccountingInformation,
                &mut accounting as *mut _ as *mut c_void,
                std::mem::size_of_val(&accounting) as u32,
                None,
            )?;
        }
        if accounting.ActiveProcesses == 0 {
            return Ok(());
        }
    }
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
    wait_for_job_tree: bool,
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
        )
        .context("LogonUserW failed for the isolated Windows account")?;
    }

    let mut environment: *mut c_void = std::ptr::null_mut();
    let result = unsafe {
        let environment_created = match CreateEnvironmentBlock(&mut environment, token, false) {
            Ok(()) => true,
            Err(error) if error.code() == E_ACCESSDENIED => false,
            Err(error) => {
                return Err(error).context("CreateEnvironmentBlock failed for the isolated account")
            }
        };
        let mut launch_environment =
            environment_created.then(|| corrected_environment(environment, username));
        let mut startup = STARTUPINFOW::default();
        startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        if visible_desktop {
            startup.lpDesktop = PWSTR(desktop_w.as_ptr() as *mut u16);
        }
        let job = if let Some(name) = &job_w {
            Some(
                CreateJobObjectW(None, PCWSTR(name.as_ptr()))
                    .context("CreateJobObjectW failed for the isolated instance")?,
            )
        } else {
            None
        };
        if let Some(job) = job {
            grant_job_access(job, username)
                .context("granting the isolated account access to its Job Object")?;
        }
        let completion = if wait_for_job_tree {
            Some(configure_broker_job(
                job.context("completion-port broker requires a Job Object")?,
            )?)
        } else {
            None
        };
        let stop_event = if wait_for_job_tree {
            job_name.context("completion-port broker requires a named Job Object")?;
            let name_w = wide(&format!(r"Local\AppMux.StopEvent.v1.{username}"));
            Some(
                CreateEventW(None, true, false, PCWSTR(name_w.as_ptr()))
                    .context("creating the isolated instance stop event")?,
            )
        } else {
            None
        };
        let flags = if job.is_some() {
            CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB
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
            launch_environment
                .as_mut()
                .map(|block| block.as_mut_ptr() as *const c_void),
            cwd_w
                .as_ref()
                .map(|v| PCWSTR(v.as_ptr()))
                .unwrap_or(PCWSTR::null()),
            &startup,
            &mut process,
        );
        let managed = if created.is_ok() {
            if let Some(job) = job {
                let result = (|| -> Result<()> {
                    let mut inherited_job = BOOL::default();
                    IsProcessInJob(process.hProcess, None, &mut inherited_job)
                        .context("IsProcessInJob failed for the alternate-user process")?;
                    if inherited_job.as_bool() {
                        if wait_for_job_tree {
                            AssignProcessToJobObject(job, process.hProcess).context(
                                "AssignProcessToJobObject failed for the nested isolated instance",
                            )?;
                        }
                        if ResumeThread(process.hThread) == u32::MAX {
                            return Err(windows::core::Error::from_win32()).context(
                                "ResumeThread failed for the process in its inherited Job Object",
                            );
                        }
                        return Ok(());
                    }
                    AssignProcessToJobObject(job, process.hProcess)
                        .context("AssignProcessToJobObject failed for the isolated instance")?;
                    if !wait_for_job_tree {
                        let mut remote_job = HANDLE::default();
                        DuplicateHandle(
                            GetCurrentProcess(),
                            job,
                            process.hProcess,
                            &mut remote_job,
                            0,
                            false,
                            DUPLICATE_SAME_ACCESS,
                        )
                        .context(
                            "DuplicateHandle failed while retaining the isolated Job Object",
                        )?;
                    }
                    if ResumeThread(process.hThread) == u32::MAX {
                        return Err(windows::core::Error::from_win32())
                            .context("ResumeThread failed for the isolated process");
                    }
                    Ok(())
                })();
                if !wait_for_job_tree || result.is_err() {
                    let _ = CloseHandle(job);
                }
                result
            } else {
                Ok(())
            }
        } else {
            if let Some(stop_event) = stop_event {
                let _ = CloseHandle(stop_event);
            }
            if let Some(completion) = completion {
                let _ = CloseHandle(completion);
            }
            if let Some(job) = job {
                let _ = CloseHandle(job);
            }
            Ok(())
        };
        if let Err(error) = managed {
            if let Some(stop_event) = stop_event {
                let _ = CloseHandle(stop_event);
            }
            if let Some(completion) = completion {
                let _ = CloseHandle(completion);
            }
            if !process.hProcess.is_invalid() {
                let _ = TerminateProcess(process.hProcess, 1);
            }
            if !process.hThread.is_invalid() {
                let _ = CloseHandle(process.hThread);
            }
            if !process.hProcess.is_invalid() {
                let _ = CloseHandle(process.hProcess);
            }
            if environment_created {
                let _ = DestroyEnvironmentBlock(environment);
            }
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
        if created.is_ok() && wait_for_job_tree {
            wait_for_job_to_empty(
                job.context("completion-port broker lost its Job Object")?,
                completion.context("completion-port broker lost its completion port")?,
                stop_event.context("completion-port broker lost its stop event")?,
            )?;
            let mut code = 0;
            GetExitCodeProcess(process.hProcess, &mut code)?;
            exit_code = Some(code);
        } else if created.is_ok() && wait {
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
        if wait_for_job_tree {
            if let Some(stop_event) = stop_event {
                let _ = CloseHandle(stop_event);
            }
            if let Some(completion) = completion {
                let _ = CloseHandle(completion);
            }
            if let Some(job) = job {
                let _ = CloseHandle(job);
            }
        }
        if environment_created {
            let _ = DestroyEnvironmentBlock(environment);
        }
        let _ = CloseHandle(token);
        created.context("CreateProcessWithLogonW failed for the isolated account")?;
        Ok::<(u32, bool, Option<u32>), anyhow::Error>((pid, waited, exit_code))
    }?;
    let (pid, waited, exit_code) = result;
    if wait_for_job_tree {
        return Ok(pid);
    }
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

fn initialize_known_folders() -> Result<()> {
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
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    for scheme in ["http", "https", "slack"] {
        let class = format!(r"Software\Classes\{scheme}");
        let command = format!(r"{class}\shell\open\command");
        let managed = hkcu
            .open_subkey(&command)
            .ok()
            .and_then(|key| key.get_value::<String, _>("").ok())
            .is_some_and(|value| {
                let value = value.to_ascii_lowercase();
                value.contains("appmux-profile-init") || value.contains(r"\appmux\tools\")
            });
        if managed {
            let _ = hkcu.delete_subkey_all(&class);
        }
    }
    Ok(())
}

pub fn initialize_profile(
    protocol: Option<&str>,
    helper: Option<&Path>,
    host: Option<&Path>,
    hosted_app: Option<&Path>,
    shim_target: Option<&Path>,
    profile: Option<&Path>,
    auth_app: Option<&Path>,
    status: Option<&Path>,
    icon: Option<&Path>,
    app_user_model_id: Option<&str>,
) -> Result<()> {
    let options = ProfileInitializationOptions {
        protocol,
        helper,
        host,
        hosted_app,
        shim_target,
        profile,
        auth_app,
        status,
        icon,
        app_user_model_id,
    };
    let Some((protocol, config)) = complete_profile_initialization(options)? else {
        initialize_known_folders()?;
        return Ok(());
    };
    initialize_known_folders()?;
    let helper = config.helper;
    let host = config.host;
    let hosted_app = config.hosted_app;
    let shim_target = config.shim_target;
    let profile = config.profile;
    let auth_app = config.auth_app;
    let icon = config.icon;
    let user_profile = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .context("Tier D profile has no USERPROFILE")?;
    let public_profile = std::env::var_os("PUBLIC")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Users\Public"));
    validate_profile_protocol_config(protocol, &user_profile, &public_profile, config)?;
    let hidden_paths = [
        helper,
        host,
        hosted_app,
        shim_target,
        profile,
        auth_app,
        icon,
    ];
    anyhow::ensure!(
        hidden_paths.into_iter().all(Path::exists),
        "Tier D authentication files are missing"
    );
    let canonical_profile =
        std::fs::canonicalize(&user_profile).context("resolving the isolated USERPROFILE path")?;
    for path in hidden_paths {
        let canonical = std::fs::canonicalize(path)
            .with_context(|| format!("resolving Tier D authentication path {}", path.display()))?;
        anyhow::ensure!(
            canonical.starts_with(&canonical_profile),
            "Tier D authentication file resolves outside the isolated profile"
        );
    }
    Ok(())
}

struct BrandWindow {
    pid: u32,
    icon: HANDLE,
}

unsafe extern "system" fn brand_window(
    hwnd: windows::Win32::Foundation::HWND,
    lparam: windows::Win32::Foundation::LPARAM,
) -> windows::Win32::Foundation::BOOL {
    use windows::Win32::Foundation::{BOOL, LPARAM, WPARAM};
    use windows::Win32::UI::WindowsAndMessaging::{
        GetWindowThreadProcessId, SendMessageW, WM_SETICON,
    };

    let state = &*(lparam.0 as *const BrandWindow);
    let mut pid = 0;
    GetWindowThreadProcessId(hwnd, Some(&mut pid));
    if pid == state.pid {
        SendMessageW(hwnd, WM_SETICON, WPARAM(1), LPARAM(state.icon.0 as isize));
        SendMessageW(hwnd, WM_SETICON, WPARAM(0), LPARAM(state.icon.0 as isize));
    }
    BOOL(1)
}

pub fn host_electron(
    host: &Path,
    app: &Path,
    shim_target: Option<&Path>,
    profile: Option<&Path>,
    auth_app: Option<&Path>,
    status: Option<&Path>,
    icon: &Path,
    app_user_model_id: &str,
    job_name: Option<&str>,
    uri: Option<&str>,
) -> Result<()> {
    use windows::Win32::Foundation::LPARAM;
    use windows::Win32::UI::WindowsAndMessaging::{
        EnumWindows, LoadImageW, IMAGE_ICON, LR_DEFAULTSIZE, LR_LOADFROMFILE,
    };

    anyhow::ensure!(
        host.exists()
            && app.exists()
            && shim_target.is_none_or(Path::exists)
            && profile.is_none_or(Path::exists)
            && auth_app.is_none_or(Path::exists),
        "Tier C Electron host files are missing"
    );
    if let Some(uri) = uri {
        validate_callback_uri(uri)?;
    }
    let held_job = if let Some(name) = job_name {
        anyhow::ensure!(
            name.starts_with(r"Local\AppMux.TierC.")
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '\\')),
            "invalid callback job name"
        );
        let name_w = wide(name);
        Some(unsafe { CreateJobObjectW(None, PCWSTR(name_w.as_ptr()))? })
    } else {
        None
    };
    std::env::remove_var("ELECTRON_RUN_AS_NODE");
    let mut command = std::process::Command::new(host);
    command
        .arg(app)
        .arg(format!("--app-user-model-id={app_user_model_id}"))
        .arg(format!("--icon={}", icon.display()));
    if let Some(target) = shim_target {
        command.arg(format!("--shim-target={}", target.display()));
    }
    if let Some(profile) = profile {
        command.arg(format!("--profile={}", profile.display()));
    }
    if let Some(auth_app) = auth_app {
        let helper = std::env::current_exe().context("Tier C helper path is unavailable")?;
        command.arg(format!("--auth-host={}", host.display()));
        command.arg(format!("--auth-app={}", auth_app.display()));
        command.arg(format!("--helper={}", helper.display()));
    }
    if let Some(status) = status {
        command.arg(format!("--status={}", status.display()));
    }
    if uri.is_some() {
        command
            .arg("--callback-stdin")
            .stdin(std::process::Stdio::piped());
    }
    let mut child = command.spawn()?;
    if let Some(job) = held_job {
        use std::os::windows::io::AsRawHandle;
        if let Err(error) =
            unsafe { AssignProcessToJobObject(job, HANDLE(child.as_raw_handle() as *mut c_void)) }
        {
            let _ = child.kill();
            let _ = child.wait();
            unsafe {
                let _ = CloseHandle(job);
            }
            return Err(error).context("assigning hosted Electron to its Job Object");
        }
    }
    if let Some(uri) = uri {
        let write_result = (|| -> Result<()> {
            let mut input = child
                .stdin
                .take()
                .context("hosted Electron callback stdin is unavailable")?;
            input
                .write_all(uri.as_bytes())
                .context("writing the callback URI to hosted Electron stdin")?;
            Ok(())
        })();
        if let Err(error) = write_result {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    }
    let icon_w = wide(&icon.to_string_lossy());
    let icon = unsafe {
        LoadImageW(
            None,
            PCWSTR(icon_w.as_ptr()),
            IMAGE_ICON,
            0,
            0,
            LR_LOADFROMFILE | LR_DEFAULTSIZE,
        )?
    };
    let state = BrandWindow {
        pid: child.id(),
        icon,
    };
    if let Some(job) = held_job {
        let started = std::time::Instant::now();
        let mut root_status = None;
        let mut tree_started = false;
        loop {
            unsafe {
                let _ = EnumWindows(
                    Some(brand_window),
                    LPARAM(&state as *const BrandWindow as isize),
                );
            }
            if root_status.is_none() {
                root_status = child.try_wait()?;
            }
            let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
            unsafe {
                QueryInformationJobObject(
                    job,
                    JobObjectBasicAccountingInformation,
                    &mut accounting as *mut _ as *mut c_void,
                    std::mem::size_of_val(&accounting) as u32,
                    None,
                )?;
            }
            if accounting.ActiveProcesses > 2
                || accounting.ActiveProcesses > 1
                    && started.elapsed() >= std::time::Duration::from_secs(3)
            {
                tree_started = true;
            }
            if accounting.ActiveProcesses <= 1 {
                unsafe {
                    let _ = CloseHandle(job);
                }
                if tree_started {
                    return Ok(());
                }
                let status = root_status.or_else(|| child.try_wait().ok().flatten());
                anyhow::ensure!(
                    status.is_some_and(|status| status.success()),
                    "hosted Electron process exited before its process tree started"
                );
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }
    for _ in 0..240 {
        unsafe {
            let _ = EnumWindows(
                Some(brand_window),
                LPARAM(&state as *const BrandWindow as isize),
            );
        }
        if let Some(status) = child.try_wait()? {
            anyhow::ensure!(
                status.success(),
                "hosted Electron process exited with {status}"
            );
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    let status = child.wait()?;
    anyhow::ensure!(
        status.success(),
        "hosted Electron process exited with {status}"
    );
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
            entry
                .file_type()
                .map(|kind| kind.is_dir() && !kind.is_symlink())
                .unwrap_or(false)
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
        let kind = entry.file_type()?;
        use std::os::windows::fs::MetadataExt;
        let attributes = std::fs::symlink_metadata(entry.path())?.file_attributes();
        anyhow::ensure!(
            !kind.is_symlink() && attributes & 0x400 == 0,
            "refusing reparse point in managed-copy source: {}",
            entry.path().display()
        );
        let name = entry.file_name();
        let lower = name.to_string_lossy().to_ascii_lowercase();
        if lower == "packages" || (lower.starts_with("app-") && newest_app.as_ref() != Some(&name))
        {
            continue;
        }
        let target = destination.join(&name);
        if kind.is_dir() {
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
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn sha256_file_bytes(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
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

fn patch_slack_electron_fuse(bytes: &mut [u8]) -> Result<bool> {
    let sentinels: Vec<_> = bytes
        .windows(ELECTRON_FUSE_SENTINEL.len())
        .enumerate()
        .filter_map(|(index, value)| (value == ELECTRON_FUSE_SENTINEL).then_some(index))
        .collect();
    anyhow::ensure!(
        sentinels.len() == 1,
        "Slack Tier D Electron fuse sentinel mismatch"
    );
    let header = sentinels[0] + ELECTRON_FUSE_SENTINEL.len();
    let fuses = bytes
        .get_mut(header..header + SLACK_451191_FUSES.len())
        .context("Slack Tier D Electron fuse block is truncated")?;
    if fuses == SLACK_451191_PATCHED_FUSES {
        return Ok(false);
    }
    anyhow::ensure!(
        fuses == SLACK_451191_FUSES,
        "Slack Tier D Electron fuse layout mismatch"
    );
    fuses.copy_from_slice(SLACK_451191_PATCHED_FUSES);
    Ok(true)
}

fn slack_singleton_replacement() -> Vec<u8> {
    let mut replacement = b"true".to_vec();
    replacement.resize(SLACK_451191_SINGLETON.len(), b' ');
    replacement
}

fn patch_slack_singleton(bytes: &mut [u8]) -> Result<bool> {
    let replacement = slack_singleton_replacement();
    let originals: Vec<_> = bytes
        .windows(SLACK_451191_SINGLETON.len())
        .enumerate()
        .filter_map(|(index, value)| (value == SLACK_451191_SINGLETON).then_some(index))
        .collect();
    let patched: Vec<_> = bytes
        .windows(replacement.len())
        .enumerate()
        .filter_map(|(index, value)| (value == replacement).then_some(index))
        .collect();
    match (originals.as_slice(), patched.as_slice()) {
        ([index], []) => {
            bytes[*index..*index + replacement.len()].copy_from_slice(&replacement);
            Ok(true)
        }
        ([], [_]) => Ok(false),
        _ => bail!("Slack Tier D singleton signature mismatch; refusing to patch copied archive"),
    }
}

fn patch_slack_open_external(bytes: &mut [u8]) -> Result<bool> {
    anyhow::ensure!(
        SLACK_451191_OPEN_EXTERNAL.len() == SLACK_451191_APPMUX_OPEN_EXTERNAL.len(),
        "Slack Tier D external-link replacement length mismatch"
    );
    let originals: Vec<_> = bytes
        .windows(SLACK_451191_OPEN_EXTERNAL.len())
        .enumerate()
        .filter_map(|(index, value)| (value == SLACK_451191_OPEN_EXTERNAL).then_some(index))
        .collect();
    let patched: Vec<_> = bytes
        .windows(SLACK_451191_APPMUX_OPEN_EXTERNAL.len())
        .enumerate()
        .filter_map(|(index, value)| (value == SLACK_451191_APPMUX_OPEN_EXTERNAL).then_some(index))
        .collect();
    match (originals.as_slice(), patched.as_slice()) {
        ([index], []) => {
            bytes[*index..*index + SLACK_451191_APPMUX_OPEN_EXTERNAL.len()]
                .copy_from_slice(SLACK_451191_APPMUX_OPEN_EXTERNAL);
            Ok(true)
        }
        ([], [_]) => Ok(false),
        _ => {
            bail!("Slack Tier D external-link signature mismatch; refusing to patch copied archive")
        }
    }
}

fn patch_slack_open_external_selector(bytes: &mut [u8]) -> Result<bool> {
    anyhow::ensure!(
        SLACK_451191_OPEN_EXTERNAL_SELECTOR.len() == SLACK_451191_APPMUX_SELECTOR.len(),
        "Slack Tier D external-link selector replacement length mismatch"
    );
    let originals: Vec<_> = bytes
        .windows(SLACK_451191_OPEN_EXTERNAL_SELECTOR.len())
        .enumerate()
        .filter_map(|(index, value)| {
            (value == SLACK_451191_OPEN_EXTERNAL_SELECTOR).then_some(index)
        })
        .collect();
    let patched: Vec<_> = bytes
        .windows(SLACK_451191_APPMUX_SELECTOR.len())
        .enumerate()
        .filter_map(|(index, value)| (value == SLACK_451191_APPMUX_SELECTOR).then_some(index))
        .collect();
    match (originals.as_slice(), patched.as_slice()) {
        ([index], []) => {
            bytes[*index..*index + SLACK_451191_APPMUX_SELECTOR.len()]
                .copy_from_slice(SLACK_451191_APPMUX_SELECTOR);
            Ok(true)
        }
        ([], [_]) => Ok(false),
        _ => bail!(
            "Slack Tier D external-link selector signature mismatch; refusing to patch copied archive"
        ),
    }
}

fn patch_figma_signature(bytes: &mut [u8], original: &[u8], prefix: &[u8]) -> Result<bool> {
    anyhow::ensure!(
        prefix.len() <= original.len(),
        "Figma replacement is too long"
    );
    let mut replacement = vec![b' '; original.len()];
    replacement[..prefix.len()].copy_from_slice(prefix);
    let originals: Vec<_> = bytes
        .windows(original.len())
        .enumerate()
        .filter_map(|(index, value)| (value == original).then_some(index))
        .collect();
    let patched: Vec<_> = bytes
        .windows(replacement.len())
        .enumerate()
        .filter_map(|(index, value)| (value == replacement).then_some(index))
        .collect();
    match (originals.as_slice(), patched.as_slice()) {
        ([index], []) => {
            bytes[*index..*index + replacement.len()].copy_from_slice(&replacement);
            Ok(true)
        }
        ([], [_]) => Ok(false),
        _ => bail!("Figma Tier D signature mismatch; refusing to patch copied archive"),
    }
}

fn patch_figma_archive(bytes: &mut [u8]) -> Result<bool> {
    let mut changed = false;
    changed |= patch_figma_signature(bytes, FIGMA_126816_SINGLETON, b"true")?;
    changed |= patch_figma_signature(bytes, FIGMA_126816_UPDATE_GATE, b"await 0")?;
    changed |= patch_figma_signature(bytes, FIGMA_126816_APPDATA, b"zl.app.getPath(\"userData\")")?;
    Ok(changed)
}

pub fn preflight_tier_d(plan: &LaunchPlan) -> Result<()> {
    let Some(adapter) = plan.recipe.tier_d_patch.as_deref() else {
        return Ok(());
    };
    let resources = plan
        .exe
        .parent()
        .context("Tier D executable has no parent")?
        .join("resources");
    let source_asar = resources.join("app.asar");
    match adapter {
        "slack-singleton-v1" => {
            anyhow::ensure!(
                sha256_file(&plan.exe)?.eq_ignore_ascii_case(SLACK_451191_EXE_SHA256),
                "Slack adapter update required: executable hash is not supported"
            );
            anyhow::ensure!(
                sha256_file(&source_asar)?.eq_ignore_ascii_case(SLACK_451191_ASAR_SHA256),
                "Slack adapter update required: app.asar hash is not supported"
            );
            let mut executable = std::fs::read(&plan.exe)?;
            patch_slack_electron_fuse(&mut executable)?;
            let mut archive = std::fs::read(source_asar)?;
            patch_slack_singleton(&mut archive)?;
            patch_slack_open_external(&mut archive)?;
            patch_slack_open_external_selector(&mut archive)?;
        }
        "figma-owner-host-v1" => {
            anyhow::ensure!(
                plan.recipe.tier_c_electron_host.as_deref() == Some(FIGMA_ELECTRON_VERSION)
                    && plan.recipe.tier_c_electron_sha256.as_deref()
                        == Some(FIGMA_ELECTRON_ARCHIVE_SHA256)
                    && plan.recipe.tier_c_electron_exe_sha256.as_deref()
                        == Some(FIGMA_ELECTRON_EXE_SHA256),
                "Figma Electron host metadata mismatch"
            );
            anyhow::ensure!(
                plan.recipe.tier_d_owner_host,
                "Figma adapter requires owner-host mode"
            );
            anyhow::ensure!(
                sha256_file(&plan.exe)?.eq_ignore_ascii_case(FIGMA_126816_EXE_SHA256),
                "Figma adapter update required: executable hash is not supported"
            );
            anyhow::ensure!(
                sha256_file(&source_asar)?.eq_ignore_ascii_case(FIGMA_126816_ASAR_SHA256),
                "Figma adapter update required: app.asar hash is not supported"
            );
            anyhow::ensure!(
                sha256_file(&resources.join("app.asar.unpacked").join("bindings.node"))?
                    .eq_ignore_ascii_case(FIGMA_126816_BINDINGS_SHA256),
                "Figma bindings hash is not supported"
            );
            anyhow::ensure!(
                sha256_file(
                    &resources
                        .join("app.asar.unpacked")
                        .join("desktop_rust.node")
                )?
                .eq_ignore_ascii_case(FIGMA_126816_DESKTOP_RUST_SHA256),
                "Figma desktop runtime hash is not supported"
            );
            anyhow::ensure!(
                sha256_file(&resources.join("FigmaAgent").join("figma_agent.exe"))?
                    .eq_ignore_ascii_case(FIGMA_126816_AGENT_SHA256),
                "Figma Agent hash is not supported"
            );
            let mut archive = std::fs::read(source_asar)?;
            patch_figma_archive(&mut archive)?;
            anyhow::ensure!(
                sha256_file_bytes(&archive).eq_ignore_ascii_case(FIGMA_126816_PATCHED_ASAR_SHA256),
                "Figma patched archive hash mismatch"
            );
        }
        _ => bail!("unknown Tier D adapter"),
    }
    Ok(())
}

fn apply_tier_d_patch(
    staged: &Instance,
    plan: &LaunchPlan,
    source_root: &Path,
    destination_root: &Path,
) -> Result<()> {
    let Some(patch) = plan.recipe.tier_d_patch.as_deref() else {
        return Ok(());
    };
    anyhow::ensure!(patch == "slack-singleton-v1", "unknown Tier D patch");
    preflight_tier_d(plan)?;
    let target_exe = staged_executable(staged, plan)?.context("Tier D app is not mirrored")?;
    let relative_exe = target_exe.strip_prefix(destination_root)?;
    let source_exe = source_root.join(relative_exe);
    std::fs::copy(&source_exe, &target_exe)?;
    let mut executable_bytes = std::fs::read(&target_exe)?;
    patch_slack_electron_fuse(&mut executable_bytes)?;
    std::fs::write(&target_exe, executable_bytes)?;
    let source_asar = source_exe
        .parent()
        .context("Tier D source executable has no parent")?
        .join("resources")
        .join("app.asar");
    let destination_asar = target_exe
        .parent()
        .context("Tier D executable has no parent")?
        .join("resources")
        .join("app.asar");
    std::fs::copy(&source_asar, &destination_asar)?;
    let mut bytes = std::fs::read(&destination_asar)?;
    patch_slack_singleton(&mut bytes)?;
    patch_slack_open_external(&mut bytes)?;
    patch_slack_open_external_selector(&mut bytes)?;
    std::fs::write(&destination_asar, bytes)?;
    Ok(())
}

fn owner_host_root(inst: &Instance) -> PathBuf {
    inst.data_dir().join("OwnerHost")
}

fn extract_managed_icon(source: &Path, destination: &Path) -> Result<()> {
    let script = destination.with_extension("icon.ps1");
    std::fs::write(&script, "param([string]$Source,[string]$Destination)\n$ErrorActionPreference='Stop'\nAdd-Type -AssemblyName System.Drawing\n$icon=[Drawing.Icon]::ExtractAssociatedIcon($Source)\nif(-not $icon){throw 'No application icon found'}\n$stream=[IO.File]::Create($Destination)\ntry{$icon.Save($stream)}finally{$stream.Dispose();$icon.Dispose()}\n")?;
    let output = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&script)
        .arg("-Source")
        .arg(source)
        .arg("-Destination")
        .arg(destination)
        .output()?;
    let _ = std::fs::remove_file(script);
    anyhow::ensure!(
        output.status.success()
            && std::fs::metadata(destination).is_ok_and(|value| value.len() > 0),
        "extracting vendor icon failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

pub fn prepare_owner_host(inst: &Instance, plan: &LaunchPlan) -> Result<()> {
    anyhow::ensure!(
        plan.recipe.tier_d_owner_host,
        "recipe is not an owner-host adapter"
    );
    preflight_tier_d(plan)?;
    let version = plan
        .recipe
        .tier_c_electron_host
        .as_deref()
        .context("owner-host adapter has no Electron version")?;
    let archive_hash = plan
        .recipe
        .tier_c_electron_sha256
        .as_deref()
        .context("owner-host adapter has no Electron archive hash")?;
    let executable_hash = plan
        .recipe
        .tier_c_electron_exe_sha256
        .as_deref()
        .context("owner-host adapter has no Electron executable hash")?;
    let host_source = ensure_electron_host(version, archive_hash, executable_hash)?;
    let root = owner_host_root(inst);
    let runtime = root.join("Runtime");
    let app = root.join("App");
    copy_install_tree(&host_source, &runtime)?;
    verify_electron_executable(&runtime.join("electron.exe"), executable_hash)?;
    let resources = plan
        .exe
        .parent()
        .context("Figma executable has no parent")?
        .join("resources");
    std::fs::create_dir_all(&app)?;
    let mut archive = std::fs::read(resources.join("app.asar"))?;
    patch_figma_archive(&mut archive)?;
    anyhow::ensure!(
        sha256_file_bytes(&archive).eq_ignore_ascii_case(FIGMA_126816_PATCHED_ASAR_SHA256),
        "Figma patched archive hash mismatch"
    );
    std::fs::write(app.join("app.asar"), archive)?;
    copy_install_tree(
        &resources.join("app.asar.unpacked"),
        &app.join("app.asar.unpacked"),
    )?;
    let build = app.join("build").join("Release");
    std::fs::create_dir_all(&build)?;
    for name in ["bindings.node", "desktop_rust.node"] {
        std::fs::copy(
            resources.join("app.asar.unpacked").join(name),
            build.join(name),
        )?;
    }
    copy_install_tree(
        &resources.join("FigmaAgent"),
        &runtime.join("resources").join("FigmaAgent"),
    )?;
    let icon = app.join("app.ico");
    extract_managed_icon(&plan.exe, &icon)?;
    let tray = app.join("assets").join("tray");
    std::fs::create_dir_all(&tray)?;
    for name in ["iconLight.ico", "iconDark.ico"] {
        std::fs::copy(&icon, tray.join(name))?;
    }
    crate::shortcut::register_start_menu_identity(inst, &plan.display, &icon)?;
    let shim = root.join("Shim");
    std::fs::create_dir_all(&shim)?;
    std::fs::write(
        shim.join("package.json"),
        r#"{"name":"figma","productName":"Figma","version":"126.8.16","main":"main.js"}"#,
    )?;
    std::fs::write(shim.join("main.js"), include_str!("tier_d_owner_shim.js"))?;
    std::fs::create_dir_all(root.join("UserData"))?;
    Ok(())
}

fn owner_host_process_active(pid: u32, expected: &Path) -> bool {
    unsafe {
        let Ok(process) = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            false,
            pid,
        ) else {
            return false;
        };
        let active = WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
        let mut path = vec![0u16; 32768];
        let mut length = path.len() as u32;
        let matches = active
            && QueryFullProcessImageNameW(
                process,
                PROCESS_NAME_FORMAT(0),
                PWSTR(path.as_mut_ptr()),
                &mut length,
            )
            .is_ok()
            && String::from_utf16_lossy(&path[..length as usize])
                .eq_ignore_ascii_case(&expected.to_string_lossy());
        let _ = CloseHandle(process);
        matches
    }
}

pub fn launch_owner_host(inst: &Instance, plan: &LaunchPlan) -> Result<u32> {
    anyhow::ensure!(
        inst.tier_d_adapter.as_deref() == plan.recipe.tier_d_patch.as_deref(),
        "owner-host adapter metadata mismatch"
    );
    let root = owner_host_root(inst);
    let runtime = root.join("Runtime").join("electron.exe");
    verify_electron_executable(&runtime, FIGMA_ELECTRON_EXE_SHA256)?;
    if inst
        .last_pid
        .is_some_and(|pid| owner_host_process_active(pid, &runtime))
    {
        return Ok(0);
    }
    anyhow::ensure!(
        sha256_file(&root.join("App").join("app.asar"))?
            .eq_ignore_ascii_case(FIGMA_126816_PATCHED_ASAR_SHA256),
        "managed Figma archive failed integrity verification"
    );
    for (path, expected) in [
        (
            root.join("App")
                .join("build")
                .join("Release")
                .join("bindings.node"),
            FIGMA_126816_BINDINGS_SHA256,
        ),
        (
            root.join("App")
                .join("build")
                .join("Release")
                .join("desktop_rust.node"),
            FIGMA_126816_DESKTOP_RUST_SHA256,
        ),
        (
            root.join("Runtime")
                .join("resources")
                .join("FigmaAgent")
                .join("figma_agent.exe"),
            FIGMA_126816_AGENT_SHA256,
        ),
    ] {
        anyhow::ensure!(
            sha256_file(&path)?.eq_ignore_ascii_case(expected),
            "managed Figma component failed integrity verification: {}",
            path.display()
        );
    }
    let app_id = crate::shortcut::app_user_model_id(inst);
    let mut command = std::process::Command::new(runtime);
    command.arg(root.join("Shim"));
    command.arg(format!(
        "--shim-target={}",
        root.join("App").join("app.asar").display()
    ));
    command.arg(format!(
        "--icon={}",
        root.join("App").join("app.ico").display()
    ));
    command.arg(format!("--app-user-model-id={app_id}"));
    command.arg(format!(
        "--user-data-dir={}",
        root.join("UserData").display()
    ));
    command.current_dir(root.join("App"));
    command.env_remove("ELECTRON_RUN_AS_NODE");
    command.env_remove("ELECTRON_NO_ASAR");
    command.stdin(std::process::Stdio::null());
    command.stdout(std::process::Stdio::null());
    command.stderr(std::process::Stdio::null());
    Ok(command.spawn()?.id())
}

pub fn stop_owner_host(inst: &Instance) -> Result<()> {
    let pid = inst
        .last_pid
        .context("owner-host instance has no recorded process")?;
    let expected = owner_host_root(inst).join("UserData");
    let script = inst.data_dir().join("stop-owner-host.ps1");
    std::fs::write(&script, "param([uint32]$ProcessId,[string]$Profile)\n$ErrorActionPreference='Stop'\n$p=Get-CimInstance Win32_Process -Filter \"ProcessId=$ProcessId\"\nif(-not $p){exit 0}\nif(-not $p.CommandLine -or $p.CommandLine.IndexOf($Profile,[StringComparison]::OrdinalIgnoreCase) -lt 0){throw 'owner-host PID identity mismatch'}\n& taskkill.exe /PID $ProcessId /T /F | Out-Null\nif($LASTEXITCODE -ne 0){throw \"taskkill failed: $LASTEXITCODE\"}\n")?;
    let output = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&script)
        .arg("-ProcessId")
        .arg(pid.to_string())
        .arg("-Profile")
        .arg(expected)
        .output()?;
    let _ = std::fs::remove_file(script);
    anyhow::ensure!(
        output.status.success(),
        "stopping owner-host instance failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
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
    apply_tier_d_patch(&staged, plan, &source, &destination)?;
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
        let auth_app = profile_root(username)
            .join("AppData")
            .join("Local")
            .join("AppMux")
            .join("Tools")
            .join("AuthBrowser");
        std::fs::create_dir_all(&auth_app)?;
        std::fs::write(
            auth_app.join("package.json"),
            r#"{"name":"appmux-auth-browser","version":"1.0.0","main":"main.js"}"#,
        )?;
        std::fs::write(auth_app.join("main.js"), include_str!("tier_d_auth.js"))?;
        grant_modify(&auth_app, username)?;
        let shim_app = profile_root(username)
            .join("AppData")
            .join("Local")
            .join("AppMux")
            .join("Tools")
            .join("SlackCompatibilityShim");
        std::fs::create_dir_all(&shim_app)?;
        std::fs::write(
            shim_app.join("package.json"),
            r#"{"name":"appmux-slack-compatibility","version":"1.0.0","main":"main.js"}"#,
        )?;
        std::fs::write(shim_app.join("main.js"), include_str!("tier_d_shim.js"))?;
        grant_modify(&shim_app, username)?;
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
            entry
                .file_type()
                .map(|kind| kind.is_dir() && !kind.is_symlink())
                .unwrap_or(false)
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

struct ElectronHostConfig {
    helper: PathBuf,
    host: PathBuf,
    app: PathBuf,
    icon: PathBuf,
    auth_app: PathBuf,
    shim_app: PathBuf,
    user_data: PathBuf,
    app_user_model_id: String,
}

fn electron_host_config(
    inst: &Instance,
    plan: &LaunchPlan,
    username: &str,
) -> Result<ElectronHostConfig> {
    let version = plan
        .recipe
        .tier_c_electron_host
        .as_deref()
        .context("recipe has no alternate Electron host")?;
    let staged = staged_executable(inst, plan)?.context("app is not mirrored")?;
    let install_root = staged
        .parent()
        .and_then(Path::parent)
        .context("mirrored Electron application has no install root")?;
    let user_data_name = plan
        .recipe
        .tier_c_user_data_dir
        .as_deref()
        .context("recipe has no Tier C user-data directory")?;
    Ok(ElectronHostConfig {
        helper: profile_root(username)
            .join("AppData")
            .join("Local")
            .join("AppMux")
            .join("Tools")
            .join("appmux-profile-init.exe"),
        host: profile_root(username)
            .join("AppData")
            .join("Local")
            .join("AppMux")
            .join("Tools")
            .join(format!("Electron-{version}"))
            .join("electron.exe"),
        app: staged
            .parent()
            .context("mirrored Electron app has no parent")?
            .join("resources")
            .join("app.asar"),
        icon: install_root.join("app.ico"),
        auth_app: profile_root(username)
            .join("AppData")
            .join("Local")
            .join("AppMux")
            .join("Tools")
            .join("AuthBrowser"),
        shim_app: profile_root(username)
            .join("AppData")
            .join("Local")
            .join("AppMux")
            .join("Tools")
            .join("SlackCompatibilityShim"),
        user_data: profile_root(username)
            .join("AppData")
            .join("Roaming")
            .join(user_data_name),
        app_user_model_id: format!(
            "AppMux.{}.{}",
            crate::paths::sanitize(&inst.app_id),
            account_name(&inst.app_id, &inst.name)
        ),
    })
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
        false,
    )?;
    Ok(())
}

fn terminate_instance_job(inst: &Instance) -> Result<bool> {
    let event_name = wide(&stop_event_name(inst));
    match unsafe { OpenEventW(EVENT_MODIFY_STATE, false, PCWSTR(event_name.as_ptr())) } {
        Ok(event) => {
            let result = unsafe { SetEvent(event) };
            unsafe {
                let _ = CloseHandle(event);
            }
            result?;
            std::thread::sleep(std::time::Duration::from_secs(2));
            return Ok(true);
        }
        Err(error) if error.code().0 as u32 == 0x8007_0002 => {}
        Err(error) => return Err(error).context("opening the isolated instance stop event"),
    }
    let job_name = format!(
        r"Local\AppMux.TierC.{}",
        account_name(&inst.app_id, &inst.name)
    );
    let job_w = wide(&job_name);
    let job = match unsafe { OpenJobObjectW(JOB_OBJECT_TERMINATE, false, PCWSTR(job_w.as_ptr())) } {
        Ok(job) => job,
        Err(error) if error.code().0 as u32 == 0x8007_0002 => return Ok(false),
        Err(error) => return Err(error).context("opening the named job for the isolated instance"),
    };
    let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
    let query = unsafe {
        QueryInformationJobObject(
            job,
            JobObjectBasicAccountingInformation,
            &mut accounting as *mut _ as *mut c_void,
            std::mem::size_of_val(&accounting) as u32,
            None,
        )
    };
    if query.is_err() || accounting.ActiveProcesses == 0 {
        unsafe {
            let _ = CloseHandle(job);
        }
        query?;
        return Ok(false);
    }
    let result = unsafe { TerminateJobObject(job, 0) };
    unsafe {
        let _ = CloseHandle(job);
    }
    result?;
    std::thread::sleep(std::time::Duration::from_secs(2));
    Ok(true)
}

pub fn stop(inst: &Instance, plan: &LaunchPlan) -> Result<()> {
    if terminate_instance_job(inst)? {
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

fn instance_job_active(inst: &Instance) -> Result<bool> {
    let event_name = wide(&stop_event_name(inst));
    match unsafe { OpenEventW(EVENT_MODIFY_STATE, false, PCWSTR(event_name.as_ptr())) } {
        Ok(event) => {
            unsafe {
                let _ = CloseHandle(event);
            }
            return Ok(true);
        }
        Err(error) if error.code().0 as u32 == 0x8007_0002 => {}
        Err(error) => return Err(error).context("opening the isolated instance broker event"),
    }
    let job_name = format!(
        r"Local\AppMux.TierC.{}",
        account_name(&inst.app_id, &inst.name)
    );
    let job_w = wide(&job_name);
    let job = match unsafe { OpenJobObjectW(JOB_OBJECT_QUERY, false, PCWSTR(job_w.as_ptr())) } {
        Ok(job) => job,
        Err(error) if error.code().0 as u32 == 0x8007_0002 => return Ok(false),
        Err(error) => return Err(error).context("opening the isolated instance Job Object"),
    };
    let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
    let result = unsafe {
        QueryInformationJobObject(
            job,
            JobObjectBasicAccountingInformation,
            &mut accounting as *mut _ as *mut c_void,
            std::mem::size_of_val(&accounting) as u32,
            None,
        )
    };
    unsafe {
        let _ = CloseHandle(job);
    }
    result?;
    Ok(accounting.ActiveProcesses > 0)
}

pub fn launch(inst: &Instance, _plan: &LaunchPlan) -> Result<u32> {
    if instance_job_active(inst)? {
        return Ok(0);
    }
    let current = std::env::current_exe()?;
    let broker = current.with_file_name("appmux.exe");
    let executable = if broker.exists() { broker } else { current };
    let mut command = std::process::Command::new(executable);
    command
        .args(["tier-c", "broker", "--app"])
        .arg(&inst.app_id)
        .arg("--instance")
        .arg(&inst.name)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());
    use std::os::windows::process::CommandExt;
    command.creation_flags(CREATE_NO_WINDOW.0 | CREATE_BREAKAWAY_FROM_JOB.0);
    let mut child = command.spawn()?;
    let pid = child.id();
    std::thread::sleep(std::time::Duration::from_secs(3));
    if let Some(status) = child.try_wait()? {
        let mut stderr = String::new();
        if let Some(mut stream) = child.stderr.take() {
            let _ = stream.read_to_string(&mut stderr);
        }
        anyhow::ensure!(
            status.success(),
            "instance broker exited during startup with {status}: {}",
            stderr.trim()
        );
    }
    Ok(pid)
}

pub fn broker_launch(inst: &Instance, plan: &LaunchPlan) -> Result<u32> {
    let username = inst
        .windows_user
        .as_deref()
        .context("Tier C instance has no Windows account; provision it first")?;
    grant_interactive_desktop(username).context(
        "refreshing interactive desktop access; run Tier C preparation with administrator approval",
    )?;
    let encrypted = std::fs::read(credential_path(inst))
        .context("Tier C credential is missing; provision the instance again")?;
    let password = unprotect(&encrypted)?;
    let staged = staged_executable(inst, plan)?;
    let job = format!(
        r"Local\AppMux.TierC.{}",
        account_name(&inst.app_id, &inst.name)
    );
    let (executable, command) = if plan.recipe.tier_c_electron_host.is_some() {
        let config = electron_host_config(inst, plan, username)?;
        let public = std::env::var_os("PUBLIC")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Users\Public"));
        let status = public
            .join("Documents")
            .join(format!("AppMux-Auth-{username}.json"));
        let command = format!(
            "{} tier-c host-electron --host {} --hosted-app {} --shim-target {} --profile {} --auth-app {} --status {} --icon {} --app-user-model-id {}",
            quote_arg(&config.helper.to_string_lossy()),
            quote_arg(&config.host.to_string_lossy()),
            quote_arg(&config.shim_app.to_string_lossy()),
            quote_arg(&config.app.to_string_lossy()),
            quote_arg(&config.user_data.to_string_lossy()),
            quote_arg(&config.auth_app.to_string_lossy()),
            quote_arg(&status.to_string_lossy()),
            quote_arg(&config.icon.to_string_lossy()),
            quote_arg(&config.app_user_model_id)
        );
        (config.helper, command)
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
    spawn_with_password(
        username,
        &password,
        &executable,
        &command,
        cwd,
        true,
        false,
        Some(&job),
        true,
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
    fn hashes_files_without_using_the_process_stack_for_the_buffer() {
        let path = std::env::temp_dir().join(format!("appmux-sha-{}.tmp", std::process::id()));
        std::fs::write(&path, b"abc").unwrap();
        assert_eq!(
            sha256_file(&path).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn windows_argument_quoting() {
        assert_eq!(quote_arg("plain"), "plain");
        assert_eq!(quote_arg("has space"), "\"has space\"");
        assert_eq!(quote_arg(r#"a"b"#), r#""a\"b""#);
    }

    #[test]
    fn profile_initialization_options_are_fail_closed() {
        assert!(
            complete_profile_initialization(ProfileInitializationOptions::default())
                .unwrap()
                .is_none()
        );

        let partial = ProfileInitializationOptions {
            protocol: Some("private-protocol-value"),
            helper: Some(Path::new(r"C:\Users\hidden\private-helper-value.exe")),
            ..ProfileInitializationOptions::default()
        };
        let error = complete_profile_initialization(partial)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "incomplete Tier D profile configuration; missing: host, hosted-app, shim-target, profile, auth-app, status, icon, app-user-model-id"
        );
        assert!(!error.contains("private-protocol-value"));
        assert!(!error.contains("private-helper-value"));

        let user_profile = Path::new(r"C:\Users\hidden account");
        let public_profile = Path::new(r"C:\Users\Public");
        let helper = user_profile.join(r"AppData\Local\AppMux\Tools\appmux-profile-init.exe");
        let host = user_profile.join(r"AppData\Local\AppMux\Tools\Electron-43\electron.exe");
        let hosted_app = user_profile.join(r"AppData\Local\AppMux\Tools\SlackCompatibilityShim");
        let shim_target = user_profile.join(r"AppData\Local\slack\app-4.51\resources\app.asar");
        let profile = user_profile.join(r"AppData\Roaming\Slack");
        let auth_app = user_profile.join(r"AppData\Local\AppMux\Tools\AuthBrowser");
        let status = public_profile.join(r"Documents\AppMux-Auth-hidden account.json");
        let icon = user_profile.join(r"AppData\Local\slack\app.ico");
        let (protocol, config) = complete_profile_initialization(ProfileInitializationOptions {
            protocol: Some("slack"),
            helper: Some(&helper),
            host: Some(&host),
            hosted_app: Some(&hosted_app),
            shim_target: Some(&shim_target),
            profile: Some(&profile),
            auth_app: Some(&auth_app),
            status: Some(&status),
            icon: Some(&icon),
            app_user_model_id: Some("AppMux.slack.hidden"),
        })
        .unwrap()
        .unwrap();
        validate_profile_protocol_config(protocol, user_profile, public_profile, config).unwrap();
    }

    #[test]
    fn deferred_host_reads_one_private_callback_and_passes_it_only_to_direct_launch() {
        let user_profile = Path::new(r"C:\Users\hidden");
        let public_profile = Path::new(r"C:\Users\Public");
        let helper = user_profile.join(r"AppData\Local\AppMux\Tools\appmux-profile-init.exe");
        let host = user_profile.join(r"AppData\Local\AppMux\Tools\Electron-43\electron.exe");
        let hosted_app = user_profile.join(r"AppData\Local\AppMux\Tools\SlackCompatibilityShim");
        let shim_target = user_profile.join(r"AppData\Local\slack\resources\app.asar");
        let profile = user_profile.join(r"AppData\Roaming\Slack");
        let auth_app = user_profile.join(r"AppData\Local\AppMux\Tools\AuthBrowser");
        let status = public_profile.join(r"Documents\AppMux-Auth-hidden.json");
        let icon = user_profile.join(r"AppData\Local\slack\app.ico");
        let plan = DeferredHostElectronPlan {
            wait_pid: 200,
            helper: &helper,
            host: &host,
            hosted_app: &hosted_app,
            shim_target: &shim_target,
            profile: &profile,
            auth_app: &auth_app,
            status: &status,
            icon: &icon,
            app_user_model_id: "AppMux.slack.hidden",
            job_name: Some(r"Local\AppMux.TierC.hidden"),
        };
        let callback = "slack://callback?test=1";
        let mut input = std::io::Cursor::new(callback.as_bytes());
        let prepared =
            prepare_deferred_host_launch(&mut input, plan, 100, user_profile, public_profile)
                .unwrap();
        assert!(!format!("{:?}", prepared.plan).contains(callback));
        let mut launched_uri = None;
        launch_prepared_deferred_host(&prepared, |launched_plan, uri| {
            assert_eq!(launched_plan.host, host);
            launched_uri = Some(uri.to_string());
            Ok(())
        })
        .unwrap();
        assert_eq!(launched_uri.as_deref(), Some(callback));

        let mut oversize = std::io::Cursor::new(vec![b'a'; MAX_DEFERRED_PROTOCOL_URI_LEN + 1]);
        assert!(read_callback_uri(&mut oversize).is_err());
        for invalid in [
            b"https://example.invalid/callback".as_slice(),
            b"Slack://callback?test=1".as_slice(),
            b"slack:".as_slice(),
            b"slack://callback\n?test=1".as_slice(),
            &[0xff, 0xfe],
        ] {
            assert!(read_callback_uri(&mut std::io::Cursor::new(invalid)).is_err());
        }
        assert!(validate_wait_pid(0, 100).is_err());
        assert!(validate_wait_pid(100, 100).is_err());
        assert!(validate_wait_pid(200, 100).is_ok());
        assert!((1_000..=120_000).contains(&DEFERRED_PROTOCOL_WAIT_MS));
    }

    #[test]
    fn slack_tier_d_patch_is_exact_idempotent_and_fail_closed() {
        let mut executable = [
            b"prefix".as_slice(),
            ELECTRON_FUSE_SENTINEL,
            SLACK_451191_FUSES,
            b"suffix".as_slice(),
        ]
        .concat();
        assert!(patch_slack_electron_fuse(&mut executable).unwrap());
        assert!(!patch_slack_electron_fuse(&mut executable).unwrap());
        assert!(executable
            .windows(SLACK_451191_PATCHED_FUSES.len())
            .any(|value| value == SLACK_451191_PATCHED_FUSES));

        let mut archive = [
            b"before".as_slice(),
            SLACK_451191_SINGLETON,
            b"after".as_slice(),
        ]
        .concat();
        assert!(patch_slack_singleton(&mut archive).unwrap());
        let once = archive.clone();
        assert!(!patch_slack_singleton(&mut archive).unwrap());
        assert_eq!(archive, once);
        assert_eq!(
            archive.len(),
            b"before".len() + SLACK_451191_SINGLETON.len() + b"after".len()
        );

        let mut external = [
            b"before".as_slice(),
            SLACK_451191_OPEN_EXTERNAL,
            b"after".as_slice(),
        ]
        .concat();
        assert!(patch_slack_open_external(&mut external).unwrap());
        let external_once = external.clone();
        assert!(!patch_slack_open_external(&mut external).unwrap());
        assert_eq!(external, external_once);
        assert!(external
            .windows(SLACK_451191_APPMUX_OPEN_EXTERNAL.len())
            .any(|value| value == SLACK_451191_APPMUX_OPEN_EXTERNAL));

        let mut selector = [
            b"before".as_slice(),
            SLACK_451191_OPEN_EXTERNAL_SELECTOR,
            b"after".as_slice(),
        ]
        .concat();
        assert!(patch_slack_open_external_selector(&mut selector).unwrap());
        let selector_once = selector.clone();
        assert!(!patch_slack_open_external_selector(&mut selector).unwrap());
        assert_eq!(selector, selector_once);

        let mut duplicate = [SLACK_451191_SINGLETON, SLACK_451191_SINGLETON].concat();
        assert!(patch_slack_singleton(&mut duplicate).is_err());
        let mut duplicate_external =
            [SLACK_451191_OPEN_EXTERNAL, SLACK_451191_OPEN_EXTERNAL].concat();
        assert!(patch_slack_open_external(&mut duplicate_external).is_err());
        let mut duplicate_selector = [
            SLACK_451191_OPEN_EXTERNAL_SELECTOR,
            SLACK_451191_OPEN_EXTERNAL_SELECTOR,
        ]
        .concat();
        assert!(patch_slack_open_external_selector(&mut duplicate_selector).is_err());
        let mut unknown = [
            b"prefix".as_slice(),
            ELECTRON_FUSE_SENTINEL,
            b"\x01\x09?????????".as_slice(),
        ]
        .concat();
        assert!(patch_slack_electron_fuse(&mut unknown).is_err());
        assert_eq!(SLACK_451191_EXE_SHA256.len(), 64);
        assert_eq!(SLACK_451191_ASAR_SHA256.len(), 64);
    }

    #[test]
    fn figma_owner_host_patch_is_exact_idempotent_and_fail_closed() {
        let mut archive = [
            b"before".as_slice(),
            FIGMA_126816_SINGLETON,
            b"middle".as_slice(),
            FIGMA_126816_UPDATE_GATE,
            b"middle".as_slice(),
            FIGMA_126816_APPDATA,
            b"after".as_slice(),
        ]
        .concat();
        assert!(patch_figma_archive(&mut archive).unwrap());
        let once = archive.clone();
        assert!(!patch_figma_archive(&mut archive).unwrap());
        assert_eq!(archive, once);
        let mut duplicate = [
            FIGMA_126816_SINGLETON,
            FIGMA_126816_SINGLETON,
            FIGMA_126816_UPDATE_GATE,
            FIGMA_126816_APPDATA,
        ]
        .concat();
        assert!(patch_figma_archive(&mut duplicate).is_err());
        let shim = include_str!("tier_d_owner_shim.js");
        assert!(shim.contains("browser-window-created"));
        assert!(shim.contains("window.setIcon(icon)"));
        assert!(shim.contains("electron.app.setAppUserModelId(appId)"));
        for hash in [
            FIGMA_126816_EXE_SHA256,
            FIGMA_126816_ASAR_SHA256,
            FIGMA_126816_PATCHED_ASAR_SHA256,
            FIGMA_ELECTRON_ARCHIVE_SHA256,
            FIGMA_ELECTRON_EXE_SHA256,
        ] {
            assert_eq!(hash.len(), 64);
        }
    }

    #[test]
    fn auth_script_routes_callback_only_to_the_existing_private_pipe() {
        let script = include_str!("tier_d_auth.js");
        assert!(script.contains("const callbackPipe = value('callback-pipe')"));
        assert!(script.contains("sendToExistingSlack(target).then("));
        assert!(script.contains("frame.writeUInt32LE(payload.length, 0)"));
        assert!(script.contains("report('callback-pipe-sent')"));
        assert!(script.contains("report('callback-pipe-error'"));
        for forbidden in [
            "'defer-host-electron'",
            "spawn(helper",
            "`--uri=${target}`",
            "`--callback-uri=${target}`",
            "shell.openExternal(target)",
            "report(target",
            "env: {",
        ] {
            assert!(!script.contains(forbidden));
        }
    }

    #[test]
    fn shim_callback_is_single_flight_and_dispatches_second_instance_without_persisting_uri() {
        let script = include_str!("tier_d_shim.js");
        assert!(script.contains("const CALLBACK_LOCK_NAME = '.appmux-callback.lock'"));
        assert!(script.contains("path.resolve(resolvedProfile, CALLBACK_LOCK_NAME)"));
        assert!(script.contains("fs.openSync(callbackLockPath, 'wx')"));
        assert!(script.contains("CALLBACK_LOCK_STALE_MS"));
        assert!(script.contains("callbackLockTimer = setTimeout"));
        assert!(script.contains("report('callback-duplicate')"));
        assert!(script.contains("process.exit(0)"));
        assert!(script.contains("process.argv = [process.execPath]"));
        assert!(!script.contains("process.argv.push(callback)"));
        assert!(script.contains("process.argv.includes('--callback-stdin')"));
        assert!(script.contains("fs.readSync(0, input"));
        assert!(!script.contains("value('callback-uri')"));
        assert!(script.contains("electron.app.listenerCount('second-instance') === 0"));
        assert!(script.contains("error.code = 'LISTENER_TIMEOUT'"));
        assert!(script.contains("setTimeout(dispatch, 50)"));
        assert!(script.contains(
            "electron.app.emit('second-instance', {}, [process.execPath, candidate], process.cwd(), {})"
        ));
        assert!(script.contains("global.appmuxOpen = hookedOpenExternal"));
        assert!(script.contains("crypto.randomBytes(24)"));
        assert!(script.contains("electron.app.setAsDefaultProtocolClient = () => true"));
        assert!(script.contains("net.createServer(socket =>"));
        assert!(script.contains("input.readUInt32LE(0)"));
        assert!(script.contains("report('callback-pipe-listening')"));
        assert!(script.contains("'callback-pipe-dispatched'"));
        assert!(script.contains("'callback-dispatched'"));
        let lock = script.find("if (!acquireCallbackLock())").unwrap();
        let require = script.find("require(target)").unwrap();
        let wait = script
            .find("electron.app.listenerCount('second-instance')")
            .unwrap();
        assert!(lock < require, "callback lock must precede loading Slack");
        assert!(
            require < wait,
            "Slack must load before waiting for its callback listener"
        );
        for forbidden in [
            "console.log",
            "console.error",
            "report(callback",
            "JSON.stringify(callback",
            "writeFileSync(callback",
            "appendFileSync(callback",
        ] {
            assert!(
                !script.contains(forbidden),
                "found sensitive sink: {forbidden}"
            );
        }
    }

    #[test]
    fn profile_protocol_config_rejects_unsupported_protocols_and_path_misuse() {
        let user_profile = Path::new(r"C:\Users\hidden");
        let public_profile = Path::new(r"C:\Users\Public");
        let helper = user_profile.join(r"AppData\Local\AppMux\Tools\appmux-profile-init.exe");
        let host = user_profile.join(r"AppData\Local\AppMux\Tools\Electron-43\electron.exe");
        let hosted_app = user_profile.join(r"AppData\Local\AppMux\Tools\SlackCompatibilityShim");
        let shim_target = user_profile.join(r"AppData\Local\slack\resources\app.asar");
        let profile = user_profile.join(r"AppData\Roaming\Slack");
        let auth_app = user_profile.join(r"AppData\Local\AppMux\Tools\AuthBrowser");
        let status = public_profile.join(r"Documents\AppMux-Auth-hidden.json");
        let icon = user_profile.join(r"AppData\Local\slack\app.ico");
        let config = ElectronHostCommandConfig {
            helper: &helper,
            host: &host,
            hosted_app: &hosted_app,
            shim_target: &shim_target,
            profile: &profile,
            auth_app: &auth_app,
            status: &status,
            icon: &icon,
            app_user_model_id: "AppMux.slack.hidden",
        };

        assert!(validate_profile_protocol_config(
            "unsupported",
            user_profile,
            public_profile,
            config
        )
        .is_err());
        let outside = Path::new(r"C:\Users\owner\resources\app.asar");
        assert!(validate_profile_protocol_config(
            "slack",
            user_profile,
            public_profile,
            ElectronHostCommandConfig {
                shim_target: outside,
                ..config
            }
        )
        .is_err());
        let traversal = user_profile.join(r"AppData\Local\..\..\owner\app.asar");
        assert!(validate_profile_protocol_config(
            "slack",
            user_profile,
            public_profile,
            ElectronHostCommandConfig {
                shim_target: &traversal,
                ..config
            }
        )
        .is_err());
    }
}

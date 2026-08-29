//! appmux is a windows-subsystem binary so Explorer launches never flash a
//! console. When run from a terminal we attach to the parent console so CLI
//! output still works; when there is no console, messages fall back to
//! message boxes.

use windows::core::PCWSTR;
use windows::Win32::System::Console::{AttachConsole, GetConsoleWindow, ATTACH_PARENT_PROCESS};
use windows::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, IDYES, MB_ICONERROR, MB_ICONINFORMATION, MB_ICONWARNING, MB_YESNO,
    MESSAGEBOX_STYLE,
};

use std::sync::atomic::{AtomicBool, Ordering};

/// When true (appmuxw.exe) and no console is attached, messages use
/// MessageBox. The console binary always uses stdio, even when piped.
static GUI_FALLBACK: AtomicBool = AtomicBool::new(false);

pub fn set_gui_fallback(enabled: bool) {
    GUI_FALLBACK.store(enabled, Ordering::Relaxed);
}

pub fn attach_parent_console() {
    unsafe {
        let _ = AttachConsole(ATTACH_PARENT_PROCESS);
    }
}

pub fn has_console() -> bool {
    unsafe { !GetConsoleWindow().0.is_null() }
}

fn use_gui() -> bool {
    GUI_FALLBACK.load(Ordering::Relaxed) && !has_console()
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn message_box(
    title: &str,
    text: &str,
    style: MESSAGEBOX_STYLE,
) -> windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_RESULT {
    let t = wide(title);
    let x = wide(text);
    unsafe { MessageBoxW(None, PCWSTR(x.as_ptr()), PCWSTR(t.as_ptr()), style) }
}

pub fn info(msg: &str) {
    if use_gui() {
        message_box("AppMux", msg, MB_ICONINFORMATION);
    } else {
        println!("{msg}");
    }
}

pub fn warn(msg: &str) {
    if use_gui() {
        message_box("AppMux", msg, MB_ICONWARNING);
    } else {
        eprintln!("warning: {msg}");
    }
}

pub fn error(msg: &str) {
    if use_gui() {
        message_box("AppMux", msg, MB_ICONERROR);
    } else {
        eprintln!("error: {msg}");
    }
}

/// Yes/no confirmation: MessageBox in GUI mode, stdin otherwise.
pub fn confirm(msg: &str) -> bool {
    if use_gui() {
        message_box("AppMux", msg, MB_YESNO | MB_ICONWARNING) == IDYES
    } else {
        println!("{msg}");
        print!("Continue? [y/N] ");
        use std::io::Write;
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            return false;
        }
        matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
    }
}

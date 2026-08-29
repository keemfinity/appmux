//! Windowless binary used by Explorer context-menu verbs so launches never
//! flash a console window. Same CLI as appmux.exe; messages fall back to
//! message boxes when no console is available.

#![windows_subsystem = "windows"]

fn main() {
    appmux::run_cli(true);
}

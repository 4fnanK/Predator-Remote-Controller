//! predator-tray.exe — notification-area companion (GUI subsystem, no console window).

#![windows_subsystem = "windows"]

fn main() {
    std::process::exit(predator::tray::main_entry());
}

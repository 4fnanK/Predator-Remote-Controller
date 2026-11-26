//! predator-service.exe — Windows service + management CLI.

fn main() {
    std::process::exit(predator::service::main_entry());
}

fn main() {
    if let Err(error) = agent_password::run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

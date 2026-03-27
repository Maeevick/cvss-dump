/// Handles the `new` subcommand — creates a new pentest session.
pub fn cmd_new() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Not yet implemented: new");
    Err(Box::from("not yet implemented"))
}

/// Handles the `open` subcommand — opens an existing session in the TUI.
pub fn cmd_open(session: &str) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Not yet implemented: open (session: {session})");
    Err(Box::from("not yet implemented"))
}

/// Handles the `list` subcommand — lists all recorded sessions.
pub fn cmd_list() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Not yet implemented: list");
    Err(Box::from("not yet implemented"))
}

/// Handles the `report` subcommand — exports a session to a markdown report.
pub fn cmd_report(session: &str) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Not yet implemented: report (session: {session})");
    Err(Box::from("not yet implemented"))
}

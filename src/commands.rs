/// Handles the `new` subcommand — creates a new pentest session.
pub fn cmd_new() -> Result<(), Box<dyn std::error::Error>> {
    println!("Not yet implemented: new");
    Ok(())
}

/// Handles the `open` subcommand — opens an existing session in the TUI.
pub fn cmd_open(session: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Not yet implemented: open (session: {session})");
    Ok(())
}

/// Handles the `list` subcommand — lists all recorded sessions.
pub fn cmd_list() -> Result<(), Box<dyn std::error::Error>> {
    println!("Not yet implemented: list");
    Ok(())
}

/// Handles the `report` subcommand — exports a session to a markdown report.
pub fn cmd_report(session: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Not yet implemented: report (session: {session})");
    Ok(())
}

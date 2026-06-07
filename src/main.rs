mod config;
mod filter;
mod interface;
mod logging;
mod nat;
mod packet;
mod relay;
mod socket;

use anyhow::{Context, Result};
use clap::Parser;
use config::Config;
use filter::Filter;
use relay::Relay;
use socket::PacketSocket;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BcrError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Interface error: {0}")]
    Interface(String),

    #[error("Socket error: {0}")]
    Socket(#[from] nix::Error),

    #[error("Permission denied: {0}. bcr requires CAP_NET_RAW or root privileges")]
    Permission(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Parser, Debug)]
#[command(name = "bcr")]
#[command(version = "0.1.0")]
#[command(about = "Modern broadcast relay for Linux", long_about = None)]
struct Cli {
    /// Input interface(s) to receive broadcasts from (can be specified multiple times)
    #[arg(short = 'i', long, required = true, num_args = 1..)]
    input: Vec<String>,

    /// Output interface(s) to relay broadcasts to (can be specified multiple times)
    #[arg(short = 'o', long, required = true)]
    output: Vec<String>,

    /// Configuration file path
    #[arg(short = 'c', long)]
    config: Option<String>,

    /// User to drop privileges to after creating sockets
    #[arg(short = 'u', long, default_value = "nobody")]
    user: String,

    /// Do not drop privileges; run as root for the entire lifetime
    #[arg(long)]
    no_drop: bool,

    /// Verbose mode (show filtered packets)
    #[arg(short = 'v', long)]
    verbose: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Validate permissions
    validate_permissions()?;

    // Load configuration (optional; error only if explicitly specified but not found)
    let config = match &cli.config {
        Some(path) => Config::from_file(path)
            .map_err(|e| BcrError::Config(format!("Failed to load config: {}", e)))?,
        None => Config::allow_all(),
    };

    // Validate environment
    validate_startup(&config, &cli.input, &cli.output)?;

    // Create sockets
    let input_sockets: Vec<_> = cli
        .input
        .iter()
        .map(|if_name| {
            PacketSocket::new(if_name)
                .with_context(|| format!("Failed to create socket for input interface '{}'", if_name))
        })
        .collect::<Result<_, _>>()?;

    let output_sockets: Vec<_> = cli
        .output
        .iter()
        .map(|if_name| {
            PacketSocket::new(if_name)
                .with_context(|| format!("Failed to create socket for output interface '{}'", if_name))
        })
        .collect::<Result<_, _>>()?;

    // Initialize relay
    let filter = Filter::new(config);
    let mut relay = Relay {
        input_sockets,
        output_sockets,
        filter,
        verbose: cli.verbose,
    };

    // Print startup banner
    println!("bcr v0.1.0 starting");
    println!("  Input:   {}", cli.input.join(", "));
    println!("  Output:  {}", cli.output.join(", "));
    println!("  Config:  {}", cli.config.as_deref().unwrap_or("(none)"));
    println!("  Drop to: {}", if cli.no_drop { "(disabled)" } else { &cli.user });
    println!("  Verbose: {}", cli.verbose);
    println!();

    // Drop privileges now that the raw sockets exist. The relay loop only does
    // read()/sendto() on already-open fds, which require no privileges. Dropping
    // from root to a non-root uid also clears all process capabilities.
    if cli.no_drop {
        eprintln!("Warning: --no-drop set, running as root for the entire lifetime");
    } else {
        drop_privileges(&cli.user)?;
    }

    // Run relay loop (blocks forever)
    relay.run()?;

    Ok(())
}

/// Drop root privileges to an unprivileged user after sockets are created.
///
/// Order matters: supplementary groups, then gid, then uid. Once the uid is
/// dropped, the gid can no longer be changed. After dropping we verify that
/// root cannot be regained as defense in depth.
fn drop_privileges(username: &str) -> Result<()> {
    use nix::unistd::{seteuid, setgid, setgroups, setuid, Uid, User};

    let user = User::from_name(username)
        .with_context(|| format!("Failed to look up user '{}'", username))?
        .ok_or_else(|| BcrError::Permission(format!("User '{}' does not exist", username)))?;

    setgroups(&[user.gid]).context("Failed to drop supplementary groups")?;
    setgid(user.gid).with_context(|| format!("Failed to setgid to {}", user.gid))?;
    setuid(user.uid).with_context(|| format!("Failed to setuid to {}", user.uid))?;

    // Confirm we cannot climb back to root.
    if seteuid(Uid::from_raw(0)).is_ok() {
        return Err(BcrError::Permission(
            "privilege drop failed: process can still regain root".to_string(),
        )
        .into());
    }

    println!(
        "Dropped privileges to '{}' (uid={}, gid={})",
        username, user.uid, user.gid
    );
    Ok(())
}

/// Validate configuration and environment before starting relay
fn validate_startup(config: &Config, input_ifs: &[String], output_ifs: &[String]) -> Result<()> {
    // Check interfaces exist and are up
    let interfaces = interface::discover_interfaces()?;
    let if_names: Vec<&str> = interfaces
        .iter()
        .filter(|i| i.is_up)
        .map(|i| i.name.as_str())
        .collect();

    for input_if in input_ifs {
        if !if_names.contains(&input_if.as_str()) {
            return Err(BcrError::Interface(format!(
                "Input interface '{}' not found or not up",
                input_if
            ))
            .into());
        }
    }

    for out_if in output_ifs {
        if !if_names.contains(&out_if.as_str()) {
            return Err(BcrError::Interface(format!(
                "Output interface '{}' not found or not up",
                out_if
            ))
            .into());
        }
    }

    // Validate config has at least one allow rule
    if config.rules.iter().all(|r| r.action == config::Action::Deny) {
        eprintln!("Warning: Configuration has no allow rules, no packets will be relayed");
    }

    Ok(())
}

/// Validate permissions (CAP_NET_RAW or root required)
fn validate_permissions() -> Result<()> {
    if !nix::unistd::geteuid().is_root() {
        return Err(BcrError::Permission(
            "bcr requires root privileges or CAP_NET_RAW capability".to_string(),
        )
        .into());
    }
    Ok(())
}

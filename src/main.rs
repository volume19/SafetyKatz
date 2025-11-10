//! SafetyKatz main entry point
//!
//! Educational tool for authorized security testing in lab environments.

use anyhow::Result;
use clap::Parser;

/// SafetyKatz - Educational LSASS dumping and PE loading tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Process ID to dump (defaults to lsass.exe if not specified)
    #[arg(short, long)]
    pid: Option<u32>,

    /// Output path for minidump file
    #[arg(short, long)]
    output_path: Option<String>,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logger
    if args.verbose {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();
    } else {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Info)
            .init();
    }

    log::info!("SafetyKatz - Educational security testing tool");
    log::warn!("WARNING: For authorized use in lab environments only");

    #[cfg(target_os = "windows")]
    {
        run_windows(args)?;
    }

    #[cfg(not(target_os = "windows"))]
    {
        anyhow::bail!("This tool requires Windows (LSASS dumping and PE loading are Windows-specific)");
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn run_windows(args: Args) -> Result<()> {
    use safety_katz_lib::*;

    // Check for high integrity (admin rights)
    log::debug!("Checking for administrative privileges...");
    match is_high_integrity() {
        Ok(true) => {
            log::info!("Running with administrative privileges");
        }
        Ok(false) => {
            anyhow::bail!("Not running with administrative privileges. This tool requires elevation.");
        }
        Err(e) => {
            anyhow::bail!("Failed to check privileges: {}", e);
        }
    }

    // TODO: Implement full workflow
    // 1. Create minidump of LSASS
    // 2. Decompress embedded Mimikatz payload
    // 3. Load PE into memory
    // 4. Execute with minidump path as argument
    // 5. Clean up minidump file

    log::info!("Full workflow not yet implemented - this is iteration 1 (project setup)");

    Ok(())
}

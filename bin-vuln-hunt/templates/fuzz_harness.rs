// IOCTL fuzzing harness template — driver vulnerability hunting
//
// Sends randomized / edge-case IOCTL buffers to a loaded driver to trigger
// crashes, hangs, or unexpected behavior. Run in an isolated VM with WinDbg
// attached (kernel debugging) to catch BSODs and analyze the crash state.
//
// Replace every <PLACEHOLDER> with values from your attack-surface mapping.
// This is a starting point — extend with targeted mutations for specific
// hypothesis validation.
//
// Prerequisites:
//   - Driver loaded: sc create <SVC> type= kernel binPath= C:\path\<DRIVER>.sys
//   - WinDbg attached to the VM via kernel debug (serial/net)
//   - Run as administrator

use std::io;
use std::ptr;
use std::thread;
use std::time::Duration;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;

// ============================================================================
// Target configuration — fill from your attack-surface mapping
// ============================================================================

/// User-mode device path (from IoCreateSymbolicLink, e.g. \\.\MyDevice)
const DEVICE_PATH: &str = r"\\.\<DEVICE>";

/// IOCTL codes to fuzz (from your IOCTL map — Phase 1)
const IOCTL_CODES: &[u32] = &[
    0x<IOCTL_1>,  // <description, e.g. "read config, METHOD_BUFFERED">
    0x<IOCTL_2>,  // <description>
    // Add all IOCTLs from your map. METHOD_NEITHER ones are highest priority.
];

/// Maximum input buffer size to test (from size checks in the handlers)
const MAX_INPUT_SIZE: usize = 4096;

/// Maximum output buffer size to request (for info-leak testing)
const MAX_OUTPUT_SIZE: usize = 4096;

/// Number of iterations per IOCTL code
const ITERATIONS: u32 = 10_000;

/// Delay between IOCTLs (milliseconds) — 0 for max speed, increase if
/// the driver queues work asynchronously and you need it to drain
const DELAY_MS: u64 = 0;

// ============================================================================
// Fuzzer
// ============================================================================

fn open_device() -> io::Result<HANDLE> {
    let path: Vec<u16> = DEVICE_PATH.encode_utf16().chain(std::iter::once(0)).collect();
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            0xC0000000, // GENERIC_READ | GENERIC_WRITE
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            Default::default(),
            HANDLE::default(),
        )
    };
    match handle {
        Ok(h) if h != INVALID_HANDLE_VALUE => Ok(h),
        Ok(_) => Err(io::Error::last_os_error()),
        Err(e) => Err(io::Error::new(io::ErrorKind::Other, e.to_string())),
    }
}

fn send_ioctl(
    device: HANDLE,
    code: u32,
    input: &[u8],
    output: &mut [u8],
) -> io::Result<u32> {
    let mut bytes_returned: u32 = 0;
    let result = unsafe {
        DeviceIoControl(
            device,
            code,
            Some(input.as_ptr() as *const _),
            input.len() as u32,
            Some(output.as_mut_ptr() as *mut _),
            output.len() as u32,
            Some(&mut bytes_returned),
            None,
        )
    };
    match result {
        Ok(_) => Ok(bytes_returned),
        Err(e) => Err(io::Error::new(io::ErrorKind::Other, e.to_string())),
    }
}

/// Generate a fuzz input buffer for a given iteration.
/// Extend this with targeted mutations based on your hypothesis.
fn generate_input(iteration: u32, max_size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; max_size];

    match iteration % 8 {
        // Edge case: empty buffer
        0 => buf.truncate(0),

        // Edge case: minimum size (1 byte)
        1 => buf.truncate(1),

        // Edge case: all 0xFF (max values in every field)
        2 => buf.iter_mut().for_each(|b| *b = 0xFF),

        // Edge case: all 0x41 (ASCII 'A' — classic overflow detector)
        3 => buf.iter_mut().for_each(|b| *b = 0x41),

        // Integer overflow probes: place large values at common size-field offsets
        4 => {
            // DWORD max at offset 0
            buf[0..4].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
            // DWORD max at offset 4
            if buf.len() >= 8 {
                buf[4..8].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
            }
        }

        // Negative size probe (signed interpretation)
        5 => {
            // -1 as DWORD at offset 0
            buf[0..4].copy_from_slice(&(-1i32).to_le_bytes());
        }

        // Near-boundary sizes
        6 => {
            // Size field = buffer_size - 1 (off-by-one probe)
            let size_val = (max_size as u32).wrapping_sub(1);
            buf[0..4].copy_from_slice(&size_val.to_le_bytes());
        }

        // Random bytes (catch unexpected parsing)
        _ => {
            // Simple PRNG for reproducibility (xorshift32)
            let mut state = iteration ^ 0xDEADBEEF;
            for byte in buf.iter_mut() {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                *byte = state as u8;
            }
        }
    }

    buf
}

fn main() -> io::Result<()> {
    println!("[*] IOCTL fuzzer for {}", DEVICE_PATH);
    println!("[*] Target IOCTLs: {:?}", IOCTL_CODES);
    println!("[*] Iterations per IOCTL: {}", ITERATIONS);
    println!("[*] Run with WinDbg attached to catch BSODs!\n");

    let device = open_device()?;
    println!("[+] Device opened: {:?}", device);

    let mut crash_count = 0u32;
    let mut success_count = 0u32;

    for &code in IOCTL_CODES {
        println!("\n[*] Fuzzing IOCTL 0x{:08X} ...", code);

        for i in 0..ITERATIONS {
            let input = generate_input(i, MAX_INPUT_SIZE);
            let mut output = vec![0u8; MAX_OUTPUT_SIZE];

            match send_ioctl(device, code, &input, &mut output) {
                Ok(bytes_returned) => {
                    success_count += 1;

                    // Check for info leak: non-zero bytes in output beyond
                    // what we'd expect from a valid response
                    if bytes_returned as usize > 0 {
                        let interesting = output[..bytes_returned as usize]
                            .windows(8)
                            .any(|w| {
                                let val = u64::from_le_bytes(w.try_into().unwrap_or([0; 8]));
                                // Kernel pointer heuristic: high 16 bits = 0xFFFF
                                (val >> 48) == 0xFFFF && val != 0xFFFFFFFFFFFFFFFF
                            });
                        if interesting {
                            println!(
                                "  [!] Potential kernel pointer leak @ IOCTL 0x{:08X}, \
                                 iter {}, returned {} bytes",
                                code, i, bytes_returned
                            );
                            println!("      Input ({} bytes): {:02X?}", input.len(),
                                     &input[..input.len().min(32)]);
                            println!("      Output: {:02X?}",
                                     &output[..bytes_returned as usize]);
                        }
                    }
                }
                Err(e) => {
                    // An error is expected for invalid input — but track it
                    crash_count += 1;
                    if i < 10 || i % 1000 == 0 {
                        println!(
                            "  [-] IOCTL 0x{:08X} iter {} error: {} (input {} bytes)",
                            code, i, e, input.len()
                        );
                    }
                }
            }

            if DELAY_MS > 0 {
                thread::sleep(Duration::from_millis(DELAY_MS));
            }
        }
    }

    println!("\n[*] Done. Successes: {}, Errors: {}", success_count, crash_count);
    println!("[*] If a BSOD occurred, check WinDbg for the crash analysis.");

    unsafe { let _ = CloseHandle(device); }
    Ok(())
}

// ============================================================================
// Cargo.toml for this harness:
//
// [package]
// name = "<driver>-fuzz"
// version = "0.1.0"
// edition = "2021"
//
// [dependencies]
// windows = { version = "0.58", features = [
//     "Win32_Foundation",
//     "Win32_Storage_FileSystem",
//     "Win32_System_IO",
// ] }
//
// [profile.release]
// opt-level = 2
// ============================================================================

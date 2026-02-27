//! Hardware discovery — USB device enumeration and introspection.
//!
//! See `docs/hardware-peripherals-design.md` for the full design.

pub mod device;
pub mod protocol;
pub mod registry;
pub mod transport;

#[cfg(feature = "hardware")]
pub mod discover;

#[cfg(feature = "hardware")]
pub mod introspect;

#[cfg(feature = "hardware")]
pub mod serial;

#[cfg(feature = "hardware")]
pub mod uf2;

#[cfg(feature = "hardware")]
pub mod pico_flash;

#[cfg(feature = "hardware")]
pub mod pico_code;

pub mod gpio;

// ── Phase 4: ToolRegistry + plugin system ─────────────────────────────────────
pub mod loader;
pub mod manifest;
pub mod subprocess;
pub mod tool_registry;

pub use device::{Device, DeviceCapabilities, DeviceContext, DeviceKind, DeviceRegistry, DeviceRuntime};
pub use gpio::{gpio_tools, GpioReadTool, GpioWriteTool};
#[cfg(feature = "hardware")]
pub use pico_code::{device_code_tools, DeviceExecTool, DeviceReadCodeTool, DeviceWriteCodeTool};
pub use protocol::{ZcCommand, ZcResponse};
pub use tool_registry::{ToolError, ToolRegistry};
pub use transport::{Transport, TransportError, TransportKind};

#[cfg(feature = "hardware")]
pub use serial::HardwareSerialTransport;

use crate::config::Config;
use anyhow::Result;

// Re-export config types so wizard can use `hardware::HardwareConfig` etc.
pub use crate::config::{HardwareConfig, HardwareTransport};

// ── Phase 5: boot() — hardware tool integration into agent loop ───────────────

/// Merge hardware tools from a [`HardwareBootResult`] into an existing tool
/// registry, deduplicating by name.
///
/// Returns a tuple of `(device_summary, added_tool_names)`.
pub fn merge_hardware_tools(
    tools: &mut Vec<Box<dyn crate::tools::Tool>>,
    hw_boot: HardwareBootResult,
) -> (String, Vec<String>) {
    let device_summary = hw_boot.device_summary.clone();
    let mut added_tool_names: Vec<String> = Vec::new();
    if !hw_boot.tools.is_empty() {
        let existing: std::collections::HashSet<String> =
            tools.iter().map(|t| t.name().to_string()).collect();
        let new_hw_tools: Vec<Box<dyn crate::tools::Tool>> = hw_boot
            .tools
            .into_iter()
            .filter(|t| !existing.contains(t.name()))
            .collect();
        if !new_hw_tools.is_empty() {
            added_tool_names = new_hw_tools.iter().map(|t| t.name().to_string()).collect();
            tracing::info!(count = new_hw_tools.len(), "Hardware registry tools added");
            tools.extend(new_hw_tools);
        }
    }
    (device_summary, added_tool_names)
}

/// Result of [`boot`]: tools to merge into the agent + device summary for the
/// system prompt.
pub struct HardwareBootResult {
    /// Tools to extend into the agent's `tools_registry`.
    pub tools: Vec<Box<dyn crate::tools::Tool>>,
    /// Human-readable device summary for the LLM system prompt.
    pub device_summary: String,
}

/// Boot the hardware subsystem: discover devices + load tool registry.
///
/// With the `hardware` feature: enumerates USB-serial devices, then
/// pre-registers any config-specified serial boards not already found by
/// discovery. [`HardwareSerialTransport`] opens the port lazily per-send,
/// so this succeeds even when the port doesn't exist at startup.
///
/// Without the feature: loads plugin tools from `~/.zeroclaw/tools/` only,
/// with an empty device registry (GPIO tools will report "no device found"
/// if called, which is correct).
#[cfg(feature = "hardware")]
pub async fn boot(peripherals: &crate::config::PeripheralsConfig) -> anyhow::Result<HardwareBootResult> {
    use device::DeviceCapabilities;

    let mut registry_inner = DeviceRegistry::discover().await;

    // Pre-register config-specified serial boards not already found by USB
    // discovery. Transport opens lazily, so the port need not exist at boot.
    if peripherals.enabled {
        let discovered_paths: std::collections::HashSet<String> = registry_inner
            .all()
            .iter()
            .filter_map(|d| d.device_path.clone())
            .collect();

        for board in &peripherals.boards {
            if board.transport != "serial" {
                continue;
            }
            let path = match &board.path {
                Some(p) if !p.is_empty() => p.clone(),
                _ => continue,
            };
            if discovered_paths.contains(&path) {
                continue; // already registered by USB discovery
            }
            let alias = registry_inner.register(
                &board.board,
                None,
                None,
                Some(path.clone()),
                None,
            );
            let transport = std::sync::Arc::new(
                HardwareSerialTransport::new(&path, board.baud),
            ) as std::sync::Arc<dyn transport::Transport>;
            let caps = DeviceCapabilities { gpio: true, ..DeviceCapabilities::default() };
            registry_inner.attach_transport(&alias, transport, caps);
            tracing::info!(
                board = %board.board,
                path = %path,
                alias = %alias,
                "pre-registered config board with lazy serial transport"
            );
        }
    }

    // BOOTSEL auto-detect: warn the user if a Pico is in BOOTSEL mode at startup.
    if uf2::find_rpi_rp2_mount().is_some() {
        tracing::info!("Pico detected in BOOTSEL mode (RPI-RP2 drive found)");
        tracing::info!("Say \"flash my pico\" to install ZeroClaw firmware automatically");
    }

    let devices = std::sync::Arc::new(tokio::sync::RwLock::new(registry_inner));
    let registry = ToolRegistry::load(devices.clone()).await?;
    let device_summary = {
        let reg = devices.read().await;
        reg.prompt_summary()
    };
    let tools = registry.into_tools();
    if !tools.is_empty() {
        tracing::info!(count = tools.len(), "Hardware registry tools loaded");
    }
    Ok(HardwareBootResult {
        tools,
        device_summary,
    })
}

/// Fallback when the `hardware` feature is disabled — plugins only.
#[cfg(not(feature = "hardware"))]
pub async fn boot(_peripherals: &crate::config::PeripheralsConfig) -> anyhow::Result<HardwareBootResult> {
    let devices = std::sync::Arc::new(
        tokio::sync::RwLock::new(DeviceRegistry::new()),
    );
    let registry = ToolRegistry::load(devices.clone()).await?;
    let device_summary = {
        let reg = devices.read().await;
        reg.prompt_summary()
    };
    let tools = registry.into_tools();
    if !tools.is_empty() {
        tracing::info!(count = tools.len(), "Hardware registry tools loaded (plugins only)");
    }
    Ok(HardwareBootResult {
        tools,
        device_summary,
    })
}

/// A hardware device discovered during auto-scan.
#[derive(Debug, Clone)]
pub struct DiscoveredDevice {
    pub name: String,
    pub detail: Option<String>,
    pub device_path: Option<String>,
    pub transport: HardwareTransport,
}

/// Auto-discover connected hardware devices.
/// Returns an empty vec on platforms without hardware support.
pub fn discover_hardware() -> Vec<DiscoveredDevice> {
    // USB/serial discovery is behind the "hardware" feature gate.
    #[cfg(feature = "hardware")]
    {
        if let Ok(devices) = discover::list_usb_devices() {
            return devices
                .into_iter()
                .map(|d| DiscoveredDevice {
                    name: d
                        .board_name
                        .unwrap_or_else(|| format!("{:04x}:{:04x}", d.vid, d.pid)),
                    detail: d.product_string,
                    device_path: None,
                    transport: if d.architecture.as_deref() == Some("native") {
                        HardwareTransport::Native
                    } else {
                        HardwareTransport::Serial
                    },
                })
                .collect();
        }
    }
    Vec::new()
}

/// Return the recommended default wizard choice index based on discovered devices.
/// 0 = Native, 1 = Tethered/Serial, 2 = Debug Probe, 3 = Software Only
pub fn recommended_wizard_default(devices: &[DiscoveredDevice]) -> usize {
    if devices.is_empty() {
        3 // software only
    } else {
        1 // tethered (most common for detected USB devices)
    }
}

/// Build a `HardwareConfig` from the wizard menu choice (0–3) and discovered devices.
pub fn config_from_wizard_choice(choice: usize, devices: &[DiscoveredDevice]) -> HardwareConfig {
    match choice {
        0 => HardwareConfig {
            enabled: true,
            transport: HardwareTransport::Native,
            ..HardwareConfig::default()
        },
        1 => {
            let serial_port = devices
                .iter()
                .find(|d| d.transport == HardwareTransport::Serial)
                .and_then(|d| d.device_path.clone());
            HardwareConfig {
                enabled: true,
                transport: HardwareTransport::Serial,
                serial_port,
                ..HardwareConfig::default()
            }
        }
        2 => HardwareConfig {
            enabled: true,
            transport: HardwareTransport::Probe,
            ..HardwareConfig::default()
        },
        _ => HardwareConfig::default(), // software only
    }
}

/// Handle `zeroclaw hardware` subcommands.
#[allow(clippy::module_name_repetitions)]
pub fn handle_command(cmd: crate::HardwareCommands, _config: &Config) -> Result<()> {
    #[cfg(not(feature = "hardware"))]
    {
        let _ = &cmd;
        println!("Hardware discovery requires the 'hardware' feature.");
        println!("Build with: cargo build --features hardware");
        return Ok(());
    }

    #[cfg(feature = "hardware")]
    match cmd {
        crate::HardwareCommands::Discover => run_discover(),
        crate::HardwareCommands::Introspect { path } => run_introspect(&path),
        crate::HardwareCommands::Info { chip } => run_info(&chip),
    }
}

#[cfg(feature = "hardware")]
fn run_discover() -> Result<()> {
    let devices = discover::list_usb_devices()?;

    if devices.is_empty() {
        println!("No USB devices found.");
        println!();
        println!("Connect a board (e.g. Nucleo-F401RE) via USB and try again.");
        return Ok(());
    }

    println!("USB devices:");
    println!();
    for d in &devices {
        let board = d.board_name.as_deref().unwrap_or("(unknown)");
        let arch = d.architecture.as_deref().unwrap_or("—");
        let product = d.product_string.as_deref().unwrap_or("—");
        println!(
            "  {:04x}:{:04x}  {}  {}  {}",
            d.vid, d.pid, board, arch, product
        );
    }
    println!();
    println!("Known boards: nucleo-f401re, nucleo-f411re, arduino-uno, arduino-mega, cp2102");

    Ok(())
}

#[cfg(feature = "hardware")]
fn run_introspect(path: &str) -> Result<()> {
    let result = introspect::introspect_device(path)?;

    println!("Device at {}:", result.path);
    println!();
    if let (Some(vid), Some(pid)) = (result.vid, result.pid) {
        println!("  VID:PID     {:04x}:{:04x}", vid, pid);
    } else {
        println!("  VID:PID     (could not correlate with USB device)");
    }
    if let Some(name) = &result.board_name {
        println!("  Board       {}", name);
    }
    if let Some(arch) = &result.architecture {
        println!("  Architecture {}", arch);
    }
    println!("  Memory map  {}", result.memory_map_note);

    Ok(())
}

#[cfg(feature = "hardware")]
fn run_info(chip: &str) -> Result<()> {
    #[cfg(feature = "probe")]
    {
        match info_via_probe(chip) {
            Ok(()) => return Ok(()),
            Err(e) => {
                println!("probe-rs attach failed: {}", e);
                println!();
                println!(
                    "Ensure Nucleo is connected via USB. The ST-Link is built into the board."
                );
                println!("No firmware needs to be flashed — probe-rs reads chip info over SWD.");
                return Err(e.into());
            }
        }
    }

    #[cfg(not(feature = "probe"))]
    {
        println!("Chip info via USB requires the 'probe' feature.");
        println!();
        println!("Build with: cargo build --features hardware,probe");
        println!();
        println!("Then run: zeroclaw hardware info --chip {}", chip);
        println!();
        println!("This uses probe-rs to attach to the Nucleo's ST-Link over USB");
        println!("and read chip info (memory map, etc.) — no firmware on target needed.");
        Ok(())
    }
}

#[cfg(all(feature = "hardware", feature = "probe"))]
fn info_via_probe(chip: &str) -> anyhow::Result<()> {
    use probe_rs::config::MemoryRegion;
    use probe_rs::{Session, SessionConfig};

    println!("Connecting to {} via USB (ST-Link)...", chip);
    let session = Session::auto_attach(chip, SessionConfig::default())
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let target = session.target();
    println!();
    println!("Chip: {}", target.name);
    println!("Architecture: {:?}", session.architecture());
    println!();
    println!("Memory map:");
    for region in target.memory_map.iter() {
        match region {
            MemoryRegion::Ram(ram) => {
                let start = ram.range.start;
                let end = ram.range.end;
                let size_kb = (end - start) / 1024;
                println!("  RAM: 0x{:08X} - 0x{:08X} ({} KB)", start, end, size_kb);
            }
            MemoryRegion::Nvm(flash) => {
                let start = flash.range.start;
                let end = flash.range.end;
                let size_kb = (end - start) / 1024;
                println!("  Flash: 0x{:08X} - 0x{:08X} ({} KB)", start, end, size_kb);
            }
            _ => {}
        }
    }
    println!();
    println!("Info read via USB (SWD) — no firmware on target needed.");
    Ok(())
}

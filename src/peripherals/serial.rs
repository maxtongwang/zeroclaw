//! Serial peripheral — STM32 and similar boards over USB CDC/serial.
//!
//! Protocol: newline-delimited JSON (ZeroClaw wire protocol).
//! Request:  {"cmd":"gpio_write","params":{"pin":13,"value":1}}
//! Response: {"cmd":"gpio_write","ok":true,"data":"done"}

use super::traits::Peripheral;
use crate::config::PeripheralBoardConfig;
use crate::tools::traits::{Tool, ToolResult};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio_serial::{SerialPortBuilderExt, SerialStream};

/// Uses the shared serial path allowlist from `crate::util`.
use crate::util::is_serial_path_allowed as is_path_allowed;

/// JSON request/response over serial — ZeroClaw wire protocol.
///
/// Wire format (must match firmware):
///   Host → Device:  `{"cmd":"gpio_write","params":{"pin":25,"value":1}}\n`
///   Device → Host:  `{"ok":true,"data":{"pin":25,"value":1,"state":"HIGH"}}\n`
async fn send_request(port: &mut SerialStream, cmd: &str, params: Value) -> anyhow::Result<Value> {
    let req = json!({ "cmd": cmd, "params": params });
    let line = format!("{}\n", req);

    tracing::info!(
        cmd = %cmd,
        bytes = %line.trim(),
        "serial write"
    );

    port.write_all(line.as_bytes()).await?;
    port.flush().await?;

    let mut buf = Vec::new();
    let mut b = [0u8; 1];
    while port.read_exact(&mut b).await.is_ok() {
        if b[0] == b'\n' {
            break;
        }
        buf.push(b[0]);
    }
    let line_str = String::from_utf8_lossy(&buf);
    tracing::info!(response = %line_str.trim(), "serial read");
    let resp: Value = serde_json::from_str(line_str.trim())?;
    Ok(resp)
}

/// Shared serial transport for tools. Pub(crate) for capabilities tool.
pub(crate) struct SerialTransport {
    port: Mutex<SerialStream>,
}

/// Timeout for serial request/response (seconds).
const SERIAL_TIMEOUT_SECS: u64 = 5;

impl SerialTransport {
    async fn request(&self, cmd: &str, args: Value) -> anyhow::Result<ToolResult> {
        let mut port = self.port.lock().await;
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(SERIAL_TIMEOUT_SECS),
            send_request(&mut port, cmd, args),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!("Serial request timed out after {}s", SERIAL_TIMEOUT_SECS)
        })??;

        let ok = resp["ok"].as_bool().unwrap_or(false);
        // Firmware responds with "data" object; stringify it for the tool output.
        let output = if resp["data"].is_null() || resp["data"].is_object() {
            resp["data"].to_string()
        } else {
            resp["data"].as_str().map(String::from).unwrap_or_else(|| resp["data"].to_string())
        };
        let error = resp["error"].as_str().map(String::from);

        Ok(ToolResult {
            success: ok,
            output,
            error,
        })
    }

    /// Phase C: fetch capabilities from device (gpio pins, led_pin).
    pub async fn capabilities(&self) -> anyhow::Result<ToolResult> {
        self.request("capabilities", json!({})).await
    }
}

/// Serial peripheral for STM32, Arduino, etc. over USB CDC.
pub struct SerialPeripheral {
    name: String,
    board_type: String,
    transport: Arc<SerialTransport>,
}

impl SerialPeripheral {
    /// Create and connect to a serial peripheral.
    #[allow(clippy::unused_async)]
    pub async fn connect(config: &PeripheralBoardConfig) -> anyhow::Result<Self> {
        let path = config
            .path
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("Serial peripheral requires path"))?;

        if !is_path_allowed(path) {
            anyhow::bail!(
                "Serial path not allowed: {}. Allowed: /dev/ttyACM*, /dev/ttyUSB*, /dev/tty.usbmodem*, /dev/cu.usbmodem*",
                path
            );
        }

        let port = tokio_serial::new(path, config.baud)
            .open_native_async()
            .map_err(|e| anyhow::anyhow!("Failed to open {}: {}", path, e))?;

        let name = format!("{}-{}", config.board, path.replace('/', "_"));
        let transport = Arc::new(SerialTransport {
            port: Mutex::new(port),
        });

        Ok(Self {
            name: name.clone(),
            board_type: config.board.clone(),
            transport,
        })
    }
}

#[async_trait]
impl Peripheral for SerialPeripheral {
    fn name(&self) -> &str {
        &self.name
    }

    fn board_type(&self) -> &str {
        &self.board_type
    }

    async fn connect(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn disconnect(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn health_check(&self) -> bool {
        self.transport
            .request("ping", json!({}))
            .await
            .map(|r| r.success)
            .unwrap_or(false)
    }

    fn tools(&self) -> Vec<Box<dyn Tool>> {
        vec![
            Box::new(GpioReadTool {
                transport: self.transport.clone(),
            }),
            Box::new(GpioWriteTool {
                transport: self.transport.clone(),
            }),
        ]
    }
}

impl SerialPeripheral {
    /// Expose transport for capabilities tool (Phase C).
    pub(crate) fn transport(&self) -> Arc<SerialTransport> {
        self.transport.clone()
    }
}

/// Tool: read GPIO pin value.
struct GpioReadTool {
    transport: Arc<SerialTransport>,
}

#[async_trait]
impl Tool for GpioReadTool {
    fn name(&self) -> &str {
        "gpio_read"
    }

    fn description(&self) -> &str {
        "Read the value (0 or 1) of a GPIO pin on a connected peripheral (e.g. STM32 Nucleo)"
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "pin": {
                    "type": "integer",
                    "description": "GPIO pin number (e.g. 13 for LED on Nucleo)"
                }
            },
            "required": ["pin"]
        })
    }

    async fn execute(&self, args: Value) -> anyhow::Result<ToolResult> {
        let pin = args
            .get("pin")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow::anyhow!("Missing 'pin' parameter"))?;
        self.transport
            .request("gpio_read", json!({ "pin": pin }))
            .await
    }
}

/// Tool: write GPIO pin value.
struct GpioWriteTool {
    transport: Arc<SerialTransport>,
}

#[async_trait]
impl Tool for GpioWriteTool {
    fn name(&self) -> &str {
        "gpio_write"
    }

    fn description(&self) -> &str {
        "Set a GPIO pin high (1) or low (0) on a connected peripheral (e.g. turn on/off LED)"
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "pin": {
                    "type": "integer",
                    "description": "GPIO pin number"
                },
                "value": {
                    "type": "integer",
                    "description": "0 for low, 1 for high"
                }
            },
            "required": ["pin", "value"]
        })
    }

    async fn execute(&self, args: Value) -> anyhow::Result<ToolResult> {
        let pin = args
            .get("pin")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow::anyhow!("Missing 'pin' parameter"))?;
        let value = args
            .get("value")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow::anyhow!("Missing 'value' parameter"))?;
        if value != 0 && value != 1 {
            return Err(anyhow::anyhow!(
                "Invalid 'value' parameter: expected 0 or 1, got {}",
                value
            ));
        }
        self.transport
            .request("gpio_write", json!({ "pin": pin, "value": value }))
            .await
    }
}

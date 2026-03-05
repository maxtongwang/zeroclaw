//! Multi-tenant workspace isolation for ZeroClaw.
//!
//! A `WorkspaceRegistry` scans `~/.zeroclaw/workspaces/` and loads all workspace
//! directories. Each workspace has an isolated `config.toml`, `memory/brain.db`,
//! identity, and channel config. The registry resolves bearer tokens to workspace
//! handles so the gateway can inject per-request workspace context.
//!
//! # Storage layout
//!
//! ```text
//! ~/.zeroclaw/
//!   config.toml                    # global defaults
//!   workspaces/
//!     {uuid}/
//!       workspace.toml             # id, display_name, created_at, token_hash, enabled
//!       config.toml                # workspace-scoped overrides
//!       memory/                    # brain.db lives here
//!       identity/                  # IDENTITY.md or identity.json
//!       channels/                  # per-channel config files
//! ```

use anyhow::{Context, Result};
use chacha20poly1305::aead::{rand_core::RngCore, OsRng};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs;

// ─── Workspace metadata (workspace.toml) ────────────────────────────────────

/// Persisted metadata for a single workspace. Stored as `workspace.toml` inside
/// the workspace directory. Never contains the raw bearer token — only its hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceToml {
    /// UUID assigned at creation time.
    pub id: String,
    /// Human-readable label shown in `zeroclaw workspace list`.
    pub display_name: String,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
    /// SHA-256 hex digest of the bearer token. Used for O(1) token lookup.
    pub token_hash: String,
    /// When `false` the workspace is skipped during registry load.
    pub enabled: bool,
}

// ─── Workspace handle ────────────────────────────────────────────────────────

/// A resolved workspace handle. Provides paths to per-workspace resources.
/// The registry holds one `Workspace` per directory; callers may clone it cheaply.
#[derive(Debug, Clone)]
pub struct Workspace {
    /// UUID — primary key in the registry.
    pub id: String,
    /// Display label.
    pub display_name: String,
    /// Whether the workspace is active.
    pub enabled: bool,
    /// Absolute path to `~/.zeroclaw/workspaces/{id}/`.
    pub dir: PathBuf,
}

impl Workspace {
    /// Path to the per-workspace `memory/` directory (contains `brain.db`).
    pub fn memory_dir(&self) -> PathBuf {
        self.dir.join("memory")
    }

    /// Path to the per-workspace `config.toml` overrides file.
    pub fn config_path(&self) -> PathBuf {
        self.dir.join("config.toml")
    }

    /// Path to the per-workspace `identity/` directory.
    pub fn identity_dir(&self) -> PathBuf {
        self.dir.join("identity")
    }

    /// Path to the per-workspace `channels/` directory.
    pub fn channels_dir(&self) -> PathBuf {
        self.dir.join("channels")
    }
}

// ─── Registry ────────────────────────────────────────────────────────────────

/// Holds all loaded workspaces and a token-hash index for O(1) resolution.
///
/// The registry is intentionally not a global singleton — callers construct it
/// from a root path and pass it where needed. This keeps the API testable and
/// avoids hidden shared state.
pub struct WorkspaceRegistry {
    /// Loaded workspaces keyed by UUID.
    pub workspaces: HashMap<String, Workspace>,
    /// `token_hash → workspace_id` for O(1) bearer token resolution.
    token_index: HashMap<String, String>,
    /// `~/.zeroclaw/` root — parent of the `workspaces/` directory.
    root: PathBuf,
}

impl WorkspaceRegistry {
    /// Scan `{root}/workspaces/` and load every valid workspace directory.
    ///
    /// Directories that are missing `workspace.toml` or have `enabled = false`
    /// are silently skipped. Parse errors emit a warning and continue.
    ///
    /// Returns an empty registry (no error) when `workspaces/` does not exist —
    /// this preserves backwards compatibility with single-workspace deployments.
    pub async fn load(root: &Path) -> Result<Self> {
        let workspaces_dir = root.join("workspaces");
        let mut workspaces = HashMap::new();
        let mut token_index = HashMap::new();

        if !workspaces_dir.exists() {
            return Ok(Self {
                workspaces,
                token_index,
                root: root.to_path_buf(),
            });
        }

        let mut entries = fs::read_dir(&workspaces_dir)
            .await
            .context("failed to read workspaces directory")?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            if !path.join("workspace.toml").exists() {
                continue;
            }
            match Self::load_one(&path).await {
                Ok(Some((ws, token_hash))) => {
                    token_index.insert(token_hash, ws.id.clone());
                    workspaces.insert(ws.id.clone(), ws);
                }
                Ok(None) => {} // disabled workspace — skip silently
                Err(e) => {
                    tracing::warn!("skipping workspace at {}: {e}", path.display());
                }
            }
        }

        Ok(Self {
            workspaces,
            token_index,
            root: root.to_path_buf(),
        })
    }

    /// Load a single workspace directory. Returns `None` for disabled workspaces.
    async fn load_one(dir: &Path) -> Result<Option<(Workspace, String)>> {
        let content = fs::read_to_string(dir.join("workspace.toml"))
            .await
            .context("failed to read workspace.toml")?;
        let meta: WorkspaceToml =
            toml::from_str(&content).context("failed to parse workspace.toml")?;

        if !meta.enabled {
            return Ok(None);
        }

        let ws = Workspace {
            id: meta.id.clone(),
            display_name: meta.display_name,
            enabled: meta.enabled,
            dir: dir.to_path_buf(),
        };
        Ok(Some((ws, meta.token_hash)))
    }

    // ─── Token resolution ────────────────────────────────────────────────────

    /// Resolve a raw bearer token to a workspace handle.
    ///
    /// Returns `None` when the token is unknown or the workspace is disabled.
    pub fn resolve(&self, token: &str) -> Option<&Workspace> {
        let hash = Self::hash_token(token);
        let id = self.token_index.get(&hash)?;
        self.workspaces.get(id)
    }

    // ─── Mutations ───────────────────────────────────────────────────────────

    /// Create a new workspace directory, write `workspace.toml`, and register it.
    ///
    /// Returns `(workspace_id, bearer_token)`. The bearer token is shown once
    /// and never stored in plaintext — callers must save it immediately.
    pub async fn create(&mut self, display_name: &str) -> Result<(String, String)> {
        let id = uuid::Uuid::new_v4().to_string();
        let token = Self::generate_token();
        let token_hash = Self::hash_token(&token);
        let created_at = Utc::now().to_rfc3339();

        let workspace_dir = self.root.join("workspaces").join(&id);
        fs::create_dir_all(workspace_dir.join("memory")).await?;
        fs::create_dir_all(workspace_dir.join("identity")).await?;
        fs::create_dir_all(workspace_dir.join("channels")).await?;

        let meta = WorkspaceToml {
            id: id.clone(),
            display_name: display_name.to_string(),
            created_at,
            token_hash: token_hash.clone(),
            enabled: true,
        };
        let toml_str =
            toml::to_string_pretty(&meta).context("failed to serialize workspace.toml")?;
        fs::write(workspace_dir.join("workspace.toml"), toml_str).await?;

        let ws = Workspace {
            id: id.clone(),
            display_name: display_name.to_string(),
            enabled: true,
            dir: workspace_dir,
        };
        self.token_index.insert(token_hash, id.clone());
        self.workspaces.insert(id.clone(), ws);

        Ok((id, token))
    }

    /// Delete a workspace by ID. Removes the on-disk directory permanently.
    ///
    /// Returns an error when the ID is unknown.
    pub async fn delete(&mut self, id: &str) -> Result<()> {
        let ws = self
            .workspaces
            .remove(id)
            .ok_or_else(|| anyhow::anyhow!("workspace '{}' not found", id))?;

        self.token_index.retain(|_, v| v != id);

        if ws.dir.exists() {
            fs::remove_dir_all(&ws.dir)
                .await
                .context("failed to remove workspace directory")?;
        }
        Ok(())
    }

    /// Rotate the bearer token for a workspace. Updates `workspace.toml` on disk.
    ///
    /// Returns the new bearer token. The old token is invalidated immediately.
    pub async fn rotate_token(&mut self, id: &str) -> Result<String> {
        let ws = self
            .workspaces
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("workspace '{}' not found", id))?;

        let new_token = Self::generate_token();
        let new_hash = Self::hash_token(&new_token);

        let toml_path = ws.dir.join("workspace.toml");
        let content = fs::read_to_string(&toml_path).await?;
        let mut meta: WorkspaceToml = toml::from_str(&content)?;

        // Invalidate old token in index before writing new one.
        self.token_index.retain(|_, v| v != id);

        meta.token_hash = new_hash.clone();
        let toml_str = toml::to_string_pretty(&meta)?;
        fs::write(&toml_path, toml_str).await?;

        self.token_index.insert(new_hash, id.to_string());
        Ok(new_token)
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    /// SHA-256 hex digest of a bearer token. Used as the stored token hash.
    fn hash_token(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Generate a 32-byte cryptographically random bearer token (hex encoded).
    fn generate_token() -> String {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }
}

// ─── CLI handler ─────────────────────────────────────────────────────────────

/// Dispatch workspace CLI subcommands. Called from `main.rs`.
pub async fn handle_command(
    command: crate::WorkspaceCommands,
    config: &crate::Config,
) -> Result<()> {
    // The zeroclaw config root is the parent of config.toml (e.g. ~/.zeroclaw/).
    let root = config
        .config_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("config path has no parent directory"))?;

    match command {
        crate::WorkspaceCommands::Create { name } => {
            let mut registry = WorkspaceRegistry::load(root).await?;
            let (id, token) = registry.create(&name).await?;
            println!("Workspace created.");
            println!("  ID:    {id}");
            println!("  Name:  {name}");
            println!("  Token: {token}");
            println!();
            println!("Save the token now — it will not be shown again.");
            Ok(())
        }

        crate::WorkspaceCommands::List => {
            let registry = WorkspaceRegistry::load(root).await?;
            if registry.workspaces.is_empty() {
                println!("No workspaces found.");
                return Ok(());
            }
            let mut workspaces: Vec<&Workspace> = registry.workspaces.values().collect();
            workspaces.sort_by_key(|w| &w.id);
            println!("{:<38}  NAME", "ID");
            println!("{}", "─".repeat(60));
            for ws in workspaces {
                println!("{:<38}  {}", ws.id, ws.display_name);
            }
            Ok(())
        }

        crate::WorkspaceCommands::Delete { id } => {
            let mut registry = WorkspaceRegistry::load(root).await?;
            registry.delete(&id).await?;
            println!("Workspace {id} deleted.");
            Ok(())
        }

        crate::WorkspaceCommands::TokenRotate { id } => {
            let mut registry = WorkspaceRegistry::load(root).await?;
            let new_token = registry.rotate_token(&id).await?;
            println!("Token rotated for workspace {id}.");
            println!("  New token: {new_token}");
            println!();
            println!("Save the token now — it will not be shown again.");
            Ok(())
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn temp_registry() -> (TempDir, WorkspaceRegistry) {
        let tmp = TempDir::new().expect("tempdir");
        let reg = WorkspaceRegistry::load(tmp.path())
            .await
            .expect("load empty registry");
        (tmp, reg)
    }

    #[tokio::test]
    async fn empty_registry_on_missing_workspaces_dir() {
        let (_tmp, reg) = temp_registry().await;
        assert!(reg.workspaces.is_empty());
    }

    #[tokio::test]
    async fn create_and_resolve() {
        let (_tmp, mut reg) = temp_registry().await;

        let (id, token) = reg.create("Test Workspace").await.expect("create");
        assert!(reg.workspaces.contains_key(&id));

        let ws = reg.resolve(&token).expect("resolve token");
        assert_eq!(ws.id, id);
        assert_eq!(ws.display_name, "Test Workspace");
    }

    #[tokio::test]
    async fn resolve_unknown_token_returns_none() {
        let (_tmp, reg) = temp_registry().await;
        assert!(reg.resolve("not-a-real-token").is_none());
    }

    #[tokio::test]
    async fn create_persists_to_disk() {
        let (tmp, mut reg) = temp_registry().await;

        let (id, _token) = reg.create("Persisted").await.expect("create");

        // Reload from disk and verify workspace is still there.
        let reg2 = WorkspaceRegistry::load(tmp.path()).await.expect("reload");
        assert!(reg2.workspaces.contains_key(&id));
    }

    #[tokio::test]
    async fn delete_removes_workspace_and_token() {
        let (_tmp, mut reg) = temp_registry().await;

        let (id, token) = reg.create("To Delete").await.expect("create");
        reg.delete(&id).await.expect("delete");

        assert!(!reg.workspaces.contains_key(&id));
        assert!(reg.resolve(&token).is_none());
    }

    #[tokio::test]
    async fn rotate_token_invalidates_old() {
        let (_tmp, mut reg) = temp_registry().await;

        let (id, old_token) = reg.create("Rotate Me").await.expect("create");
        let new_token = reg.rotate_token(&id).await.expect("rotate");

        assert!(
            reg.resolve(&old_token).is_none(),
            "old token should be invalid"
        );
        assert!(
            reg.resolve(&new_token).is_some(),
            "new token should be valid"
        );
    }

    #[tokio::test]
    async fn workspace_dirs_created() {
        let (tmp, mut reg) = temp_registry().await;

        let (id, _token) = reg.create("Dir Test").await.expect("create");
        let ws = &reg.workspaces[&id];

        assert!(ws.memory_dir().exists());
        assert!(ws.identity_dir().exists());
        assert!(ws.channels_dir().exists());
        assert!(tmp
            .path()
            .join("workspaces")
            .join(&id)
            .join("workspace.toml")
            .exists());
    }
}

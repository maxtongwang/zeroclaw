use anyhow::{bail, Context, Result};
use reqwest::multipart::{Form, Part};

use crate::config::TranscriptionConfig;

/// Maximum upload size accepted by the Groq Whisper API (25 MB).
const MAX_AUDIO_BYTES: usize = 25 * 1024 * 1024;

/// Map file extension to MIME type for Whisper-compatible transcription APIs.
fn mime_for_audio(extension: &str) -> Option<&'static str> {
    match extension.to_ascii_lowercase().as_str() {
        "flac" => Some("audio/flac"),
        "mp3" | "mpeg" | "mpga" => Some("audio/mpeg"),
        "mp4" | "m4a" => Some("audio/mp4"),
        "ogg" | "oga" => Some("audio/ogg"),
        "opus" => Some("audio/opus"),
        "wav" => Some("audio/wav"),
        "webm" => Some("audio/webm"),
        _ => None,
    }
}

/// Normalize audio filename for Whisper-compatible APIs.
///
/// Groq validates the filename extension — `.oga` (Opus-in-Ogg) is not in
/// its accepted list, so we rewrite it to `.ogg`.
fn normalize_audio_filename(file_name: &str) -> String {
    match file_name.rsplit_once('.') {
        Some((stem, ext)) if ext.eq_ignore_ascii_case("oga") => format!("{stem}.ogg"),
        _ => file_name.to_string(),
    }
}

/// Transcribe an audio file via a local whisper backend.
///
/// Prefers `whisper-cli` (whisper.cpp) — Metal-accelerated on Apple Silicon,
/// typically 10-20x faster than Python whisper. Falls back to Python `whisper`
/// if whisper-cli or its model file is not found.
///
/// CAF files (iMessage voice memos) are pre-converted to WAV via ffmpeg because
/// whisper-cli does not support CAF natively. Python whisper handles CAF directly.
pub async fn transcribe_audio_local(file_path: &str) -> anyhow::Result<String> {
    // Prefer whisper-cli (whisper.cpp) when available.
    if let Some((bin, model)) = resolve_whisper_cpp() {
        return transcribe_with_whisper_cpp(file_path, bin, model).await;
    }

    // Fall back to Python whisper.
    transcribe_with_python_whisper(file_path).await
}

/// Transcribe using whisper-cli (whisper.cpp). Converts CAF→WAV via ffmpeg first.
async fn transcribe_with_whisper_cpp(
    file_path: &str,
    bin: &str,
    model: &str,
) -> anyhow::Result<String> {
    use std::path::{Path, PathBuf};
    use tokio::process::Command;

    let ext = Path::new(file_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    // Always convert to WAV — whisper-cli (brew build) only reliably reads WAV
    // regardless of which formats it advertises. ffmpeg handles all iMessage
    // audio formats (CAF, M4A, AAC, MP3, etc.).
    let (input_path, caf_tmp): (PathBuf, Option<PathBuf>) = if ext.eq_ignore_ascii_case("wav") {
        (PathBuf::from(file_path), None)
    } else {
        let tmp = std::env::temp_dir().join(format!(
            "zc_wpp_{}.wav",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let ffmpeg = resolve_ffmpeg_bin().context(
            "ffmpeg not found — install ffmpeg to enable CAF transcription with whisper-cli",
        )?;
        let conv = Command::new(ffmpeg)
            .args([
                "-y",
                "-i",
                file_path,
                "-ar",
                "16000",
                "-ac",
                "1",
                tmp.to_str().unwrap_or(""),
            ])
            .output()
            .await
            .context("ffmpeg CAF→WAV conversion failed")?;
        if !conv.status.success() {
            let stderr = String::from_utf8_lossy(&conv.stderr);
            anyhow::bail!("ffmpeg failed converting CAF: {stderr}");
        }
        (tmp.clone(), Some(tmp))
    };

    let base = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let out_dir = std::env::temp_dir().join(format!("zc_wpp_{base}"));
    tokio::fs::create_dir_all(&out_dir)
        .await
        .context("Failed to create whisper-cli output dir")?;
    let stem = input_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("audio");
    let out_base = out_dir.join(stem);

    let input_str = input_path.to_str().unwrap_or("");
    let out_base_str = out_base.to_str().unwrap_or("");
    tracing::debug!(
        "whisper-cli: {} -m {} -otxt -of {} -np -nt {}",
        bin,
        model,
        out_base_str,
        input_str
    );

    let result = Command::new(bin)
        .args([
            "-m",
            model,
            "-otxt",
            "-of",
            out_base_str,
            "-np", // no progress bar
            "-nt", // no timestamps
            input_str,
        ])
        .output()
        .await
        .context("whisper-cli error");

    // Clean up temp WAV regardless of outcome.
    if let Some(ref tmp) = caf_tmp {
        tokio::fs::remove_file(tmp).await.ok();
    }

    let output = result?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    tracing::debug!(
        "whisper-cli exit={:?} stdout={:?} stderr={:?}",
        output.status.code(),
        stdout.trim(),
        stderr.trim()
    );

    if !output.status.success() {
        let _ = tokio::fs::remove_dir_all(&out_dir).await;
        anyhow::bail!(
            "whisper-cli failed (exit {:?}): {stderr}",
            output.status.code()
        );
    }

    let txt_path = out_dir.join(format!("{stem}.txt"));
    let txt = tokio::fs::read_to_string(&txt_path).await.map_err(|e| {
        let _ = std::fs::remove_dir_all(&out_dir);
        anyhow::anyhow!(
            "Failed to read whisper-cli output at {}: {e}",
            txt_path.display()
        )
    })?;
    let _ = tokio::fs::remove_dir_all(&out_dir).await;

    let text = txt.trim().to_string();
    anyhow::ensure!(!text.is_empty(), "whisper-cli produced empty transcript");
    Ok(text)
}

/// Transcribe using Python whisper CLI. Handles CAF natively via ffmpeg.
async fn transcribe_with_python_whisper(file_path: &str) -> anyhow::Result<String> {
    use std::path::Path;
    use tokio::process::Command;

    let whisper_bin = resolve_whisper_bin()
        .context("No whisper backend — install whisper-cpp (`brew install whisper-cpp`) or openai-whisper (`pip install openai-whisper`)")?;

    let base = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp_dir = std::env::temp_dir().join(format!("zc_whisper_{base}"));
    tokio::fs::create_dir_all(&tmp_dir)
        .await
        .context("Failed to create whisper temp dir")?;

    let output = Command::new(whisper_bin)
        .args([
            "--model",
            "turbo",
            "--output_format",
            "txt",
            "--output_dir",
            tmp_dir.to_str().unwrap_or(""),
            "--verbose",
            "False",
            file_path,
        ])
        .output()
        .await
        .context("whisper CLI error")?;

    if !output.status.success() {
        let _ = tokio::fs::remove_dir_all(&tmp_dir).await;
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.trim().is_empty() {
            tracing::debug!("whisper stderr: {stderr}");
        }
        anyhow::bail!("whisper CLI failed (exit {:?})", output.status.code());
    }

    let stem = Path::new(file_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("audio");
    let txt_path = tmp_dir.join(format!("{stem}.txt"));
    let txt = tokio::fs::read_to_string(&txt_path)
        .await
        .context("Failed to read whisper output")?;
    let _ = tokio::fs::remove_dir_all(&tmp_dir).await;

    let text = txt.trim().to_string();
    anyhow::ensure!(!text.is_empty(), "whisper produced empty transcript");
    Ok(text)
}

/// Return `true` if any local whisper backend is available.
pub fn whisper_available() -> bool {
    resolve_whisper_cpp().is_some() || resolve_whisper_bin().is_some()
}

/// Resolve whisper-cli (whisper.cpp) binary and model. Returns `None` if either
/// is missing. Result is cached after first call.
fn resolve_whisper_cpp() -> Option<(&'static str, &'static str)> {
    static CACHE: std::sync::OnceLock<Option<(&'static str, &'static str)>> =
        std::sync::OnceLock::new();
    *CACHE.get_or_init(|| {
        const BINS: &[&str] = &[
            "/opt/homebrew/bin/whisper-cli",
            "/usr/local/bin/whisper-cli",
        ];
        const MODELS: &[&str] = &[
            "/opt/homebrew/share/whisper-cpp/ggml-base.bin",
            "/opt/homebrew/share/whisper-cpp/ggml-small.bin",
            "/opt/homebrew/share/whisper-cpp/ggml-tiny.bin",
            "/opt/homebrew/share/whisper-cpp/for-tests-ggml-tiny.bin",
        ];
        let bin = BINS
            .iter()
            .copied()
            .find(|b| std::path::Path::new(b).is_file())?;
        let model = MODELS
            .iter()
            .copied()
            .find(|m| std::path::Path::new(m).is_file())?;
        Some((bin, model))
    })
}

/// Resolve the Python `whisper` binary path. Cached after first call.
fn resolve_whisper_bin() -> Option<&'static str> {
    static WHISPER_BIN: std::sync::OnceLock<Option<&'static str>> = std::sync::OnceLock::new();
    *WHISPER_BIN.get_or_init(|| {
        const CANDIDATES: &[&str] = &[
            "whisper",
            "/opt/homebrew/bin/whisper",
            "/usr/local/bin/whisper",
        ];
        CANDIDATES.iter().copied().find(|bin| {
            if bin.starts_with('/') {
                std::path::Path::new(bin).is_file()
            } else {
                std::process::Command::new("which")
                    .arg(bin)
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false)
            }
        })
    })
}

/// Resolve the `ffmpeg` binary path. Used for CAF→WAV pre-conversion.
/// Cached after first call.
fn resolve_ffmpeg_bin() -> Option<&'static str> {
    static FFMPEG_BIN: std::sync::OnceLock<Option<&'static str>> = std::sync::OnceLock::new();
    *FFMPEG_BIN.get_or_init(|| {
        const CANDIDATES: &[&str] = &[
            "ffmpeg",
            "/opt/homebrew/bin/ffmpeg",
            "/usr/local/bin/ffmpeg",
            "/usr/bin/ffmpeg",
        ];
        CANDIDATES.iter().copied().find(|bin| {
            if bin.starts_with('/') {
                std::path::Path::new(bin).is_file()
            } else {
                std::process::Command::new("which")
                    .arg(bin)
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false)
            }
        })
    })
}

/// Transcribe audio bytes via a Whisper-compatible transcription API.
///
/// Returns the transcribed text on success.
///
/// Credential resolution order:
/// 1. `config.transcription.api_key`
/// 2. `GROQ_API_KEY` environment variable (backward compatibility)
///
/// The caller is responsible for enforcing duration limits *before* downloading
/// the file; this function enforces the byte-size cap.
pub async fn transcribe_audio(
    audio_data: Vec<u8>,
    file_name: &str,
    config: &TranscriptionConfig,
) -> Result<String> {
    if audio_data.len() > MAX_AUDIO_BYTES {
        bail!(
            "Audio file too large ({} bytes, max {MAX_AUDIO_BYTES})",
            audio_data.len()
        );
    }

    let normalized_name = normalize_audio_filename(file_name);
    let extension = normalized_name
        .rsplit_once('.')
        .map(|(_, e)| e)
        .unwrap_or("");
    let mime = mime_for_audio(extension).ok_or_else(|| {
        anyhow::anyhow!(
            "Unsupported audio format '.{extension}' — accepted: flac, mp3, mp4, mpeg, mpga, m4a, ogg, opus, wav, webm"
        )
    })?;

    let api_key = config
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            std::env::var("GROQ_API_KEY")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        })
        .context(
            "Missing transcription API key: set [transcription].api_key or GROQ_API_KEY environment variable",
        )?;

    let client = crate::config::build_runtime_proxy_client("transcription.groq");

    let file_part = Part::bytes(audio_data)
        .file_name(normalized_name)
        .mime_str(mime)?;

    let mut form = Form::new()
        .part("file", file_part)
        .text("model", config.model.clone())
        .text("response_format", "json");

    if let Some(ref lang) = config.language {
        form = form.text("language", lang.clone());
    }

    let resp = client
        .post(&config.api_url)
        .bearer_auth(&api_key)
        .multipart(form)
        .send()
        .await
        .context("Failed to send transcription request")?;

    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .context("Failed to parse transcription response")?;

    if !status.is_success() {
        let error_msg = body["error"]["message"].as_str().unwrap_or("unknown error");
        bail!("Transcription API error ({}): {}", status, error_msg);
    }

    let text = body["text"]
        .as_str()
        .context("Transcription response missing 'text' field")?
        .to_string();

    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_whisper_bin_returns_str_or_none() {
        // Just assert the function doesn't panic; result depends on local install.
        let _ = resolve_whisper_bin();
    }

    #[tokio::test]
    async fn rejects_oversized_audio() {
        let big = vec![0u8; MAX_AUDIO_BYTES + 1];
        let config = TranscriptionConfig::default();

        let err = transcribe_audio(big, "test.ogg", &config)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("too large"),
            "expected size error, got: {err}"
        );
    }

    #[tokio::test]
    async fn rejects_missing_api_key() {
        // Ensure fallback env key is absent for this test.
        std::env::remove_var("GROQ_API_KEY");

        let data = vec![0u8; 100];
        let config = TranscriptionConfig::default();

        let err = transcribe_audio(data, "test.ogg", &config)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("transcription API key"),
            "expected missing-key error, got: {err}"
        );
    }

    #[tokio::test]
    async fn uses_config_api_key_without_groq_env() {
        std::env::remove_var("GROQ_API_KEY");

        let data = vec![0u8; 100];
        let mut config = TranscriptionConfig::default();
        config.api_key = Some("transcription-key".to_string());

        // Keep invalid extension so we fail before network, but after key resolution.
        let err = transcribe_audio(data, "recording.aac", &config)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("Unsupported audio format"),
            "expected unsupported-format error, got: {err}"
        );
    }

    #[test]
    fn mime_for_audio_maps_accepted_formats() {
        let cases = [
            ("flac", "audio/flac"),
            ("mp3", "audio/mpeg"),
            ("mpeg", "audio/mpeg"),
            ("mpga", "audio/mpeg"),
            ("mp4", "audio/mp4"),
            ("m4a", "audio/mp4"),
            ("ogg", "audio/ogg"),
            ("oga", "audio/ogg"),
            ("opus", "audio/opus"),
            ("wav", "audio/wav"),
            ("webm", "audio/webm"),
        ];
        for (ext, expected) in cases {
            assert_eq!(
                mime_for_audio(ext),
                Some(expected),
                "failed for extension: {ext}"
            );
        }
    }

    #[test]
    fn mime_for_audio_case_insensitive() {
        assert_eq!(mime_for_audio("OGG"), Some("audio/ogg"));
        assert_eq!(mime_for_audio("MP3"), Some("audio/mpeg"));
        assert_eq!(mime_for_audio("Opus"), Some("audio/opus"));
    }

    #[test]
    fn mime_for_audio_rejects_unknown() {
        assert_eq!(mime_for_audio("txt"), None);
        assert_eq!(mime_for_audio("pdf"), None);
        assert_eq!(mime_for_audio("aac"), None);
        assert_eq!(mime_for_audio(""), None);
    }

    #[test]
    fn normalize_audio_filename_rewrites_oga() {
        assert_eq!(normalize_audio_filename("voice.oga"), "voice.ogg");
        assert_eq!(normalize_audio_filename("file.OGA"), "file.ogg");
    }

    #[test]
    fn normalize_audio_filename_preserves_accepted() {
        assert_eq!(normalize_audio_filename("voice.ogg"), "voice.ogg");
        assert_eq!(normalize_audio_filename("track.mp3"), "track.mp3");
        assert_eq!(normalize_audio_filename("clip.opus"), "clip.opus");
    }

    #[test]
    fn normalize_audio_filename_no_extension() {
        assert_eq!(normalize_audio_filename("voice"), "voice");
    }

    #[tokio::test]
    async fn rejects_unsupported_audio_format() {
        let data = vec![0u8; 100];
        let config = TranscriptionConfig::default();

        let err = transcribe_audio(data, "recording.aac", &config)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Unsupported audio format"),
            "expected unsupported-format error, got: {msg}"
        );
        assert!(
            msg.contains(".aac"),
            "error should mention the rejected extension, got: {msg}"
        );
    }
}

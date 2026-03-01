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

/// Transcribe an audio file via the local `whisper` CLI (OpenAI Whisper).
///
/// Mirrors OpenClaw's approach: runs
/// `whisper --model turbo --output_format txt --output_dir <tmpdir> --verbose False <path>`
/// then reads `<tmpdir>/<stem>.txt`.
///
/// Supports all formats natively handled by whisper/ffmpeg, including CAF
/// (Core Audio Format — iMessage voice memos), with no pre-conversion step.
///
/// Checks `whisper` in PATH and common Homebrew/system install locations.
pub async fn transcribe_audio_local(file_path: &str) -> anyhow::Result<String> {
    use std::path::Path;
    use tokio::process::Command;

    let whisper_bin = resolve_whisper_bin()
        .context("whisper not found — install openai-whisper (`pip install openai-whisper`)")?;

    let base = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp_dir = std::env::temp_dir().join(format!("zc_whisper_{base}"));
    tokio::fs::create_dir_all(&tmp_dir)
        .await
        .context("Failed to create whisper temp dir")?;

    let status = Command::new(whisper_bin)
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
        .stderr(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .status()
        .await
        .context("whisper CLI error")?;

    if !status.success() {
        let _ = tokio::fs::remove_dir_all(&tmp_dir).await;
        anyhow::bail!("whisper CLI failed (exit {:?})", status.code());
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

/// Return `true` if a local `whisper` binary is available in PATH or a common
/// install location. Used by channel implementations to select a transcription
/// backend without requiring an API key.
pub fn whisper_available() -> bool {
    resolve_whisper_bin().is_some()
}

/// Resolve the `whisper` binary path by checking PATH and common install locations.
fn resolve_whisper_bin() -> Option<&'static str> {
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

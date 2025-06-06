use eyre::{Result, Context};
use reqwest;
use serde_json::json;
use base64::{Engine as _, engine::general_purpose};
use vibe_core::transcript::Transcript;

pub struct WebhookConfig {
    url: String,
    username: String,
    password: String,
}

impl WebhookConfig {
    pub fn from_env() -> Option<Self> {
        dotenv::dotenv().ok();
        
        let url = std::env::var("WEBHOOK_URL").ok()?;
        let username = std::env::var("WEBHOOK_USERNAME").ok()?;
        let password = std::env::var("WEBHOOK_PASSWORD").ok()?;
        
        Some(Self { url, username, password })
    }
    
    fn basic_auth_header(&self) -> String {
        let credentials = format!("{}:{}", self.username, self.password);
        let encoded = general_purpose::STANDARD.encode(credentials.as_bytes());
        format!("Basic {}", encoded)
    }
}

pub async fn send_transcript_to_webhook(transcript: &Transcript) -> Result<()> {
    let config = match WebhookConfig::from_env() {
        Some(config) => config,
        None => {
            tracing::debug!("Webhook configuration not found, skipping webhook send");
            return Ok(());
        }
    };
    
    tracing::info!("Sending transcript to webhook");
    
    // Prepare the transcript data
    let payload = json!({
        "transcript": transcript,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "processing_time_sec": transcript.processing_time_sec,
        "segments_count": transcript.segments.len(),
        "has_diarisation": transcript.segments.iter().any(|s| s.speaker.is_some())
    });
    
    let client = reqwest::Client::new();
    let response = client
        .post(&config.url)
        .header("Authorization", config.basic_auth_header())
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await
        .context("Failed to send webhook request")?;
    
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_else(|_| "No response body".to_string());
        tracing::error!("Webhook request failed with status {}: {}", status, body);
        eyre::bail!("Webhook request failed with status {}: {}", status, body);
    }
    
    tracing::info!("Successfully sent transcript to webhook");
    Ok(())
}

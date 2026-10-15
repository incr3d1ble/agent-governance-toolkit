// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Message signing and replay protection for MCP traffic.
//!
//! The canonical signing representation (`mcp-sig-v2`) is shared with the
//! Python signer (`agent_os.mcp_message_signer`) and is versioned and
//! injective: every field is length-prefixed with its UTF-8 byte length, so
//! separators inside a field can never merge two distinct field tuples into
//! one HMAC input.

use crate::mcp::clock::{Clock, NonceGenerator};
use crate::mcp::error::McpError;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Signed MCP message envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpSignedMessage {
    pub payload: String,
    pub timestamp_ms: u64,
    pub nonce: String,
    pub sender_id: Option<String>,
    pub signature: String,
}

/// Replay-detection nonce store.
pub trait McpNonceStore: Send + Sync {
    fn reserve(&self, nonce: String, expires_at_secs: u64, now_secs: u64)
        -> Result<bool, McpError>;
    fn cleanup(&self, now_secs: u64) -> Result<(), McpError>;
}

/// In-memory nonce store.
#[derive(Debug, Default)]
pub struct InMemoryNonceStore {
    nonces: Mutex<HashMap<String, u64>>,
}

impl McpNonceStore for InMemoryNonceStore {
    fn reserve(
        &self,
        nonce: String,
        expires_at_secs: u64,
        now_secs: u64,
    ) -> Result<bool, McpError> {
        let mut nonces = self
            .nonces
            .lock()
            .map_err(|_| McpError::store("nonce", "nonce store lock poisoned"))?;
        nonces.retain(|_, expires_at| *expires_at > now_secs);
        if nonces.contains_key(&nonce) {
            return Ok(false);
        }
        nonces.insert(nonce, expires_at_secs);
        Ok(true)
    }

    fn cleanup(&self, now_secs: u64) -> Result<(), McpError> {
        let mut nonces = self
            .nonces
            .lock()
            .map_err(|_| McpError::store("nonce", "nonce store lock poisoned"))?;
        nonces.retain(|_, expires_at| *expires_at > now_secs);
        Ok(())
    }
}

/// HMAC-SHA256 signer with timestamp validation and nonce replay protection.
#[derive(Clone)]
pub struct McpMessageSigner {
    secret: Vec<u8>,
    clock: Arc<dyn Clock>,
    nonce_generator: Arc<dyn NonceGenerator>,
    nonce_store: Arc<dyn McpNonceStore>,
    timestamp_tolerance: Duration,
    nonce_ttl: Duration,
}

impl McpMessageSigner {
    pub fn new(
        secret: Vec<u8>,
        clock: Arc<dyn Clock>,
        nonce_generator: Arc<dyn NonceGenerator>,
        nonce_store: Arc<dyn McpNonceStore>,
        timestamp_tolerance: Duration,
        nonce_ttl: Duration,
    ) -> Result<Self, McpError> {
        if secret.is_empty() {
            return Err(McpError::InvalidConfig(
                "message signing secret must not be empty",
            ));
        }
        if timestamp_tolerance.is_zero() || nonce_ttl.is_zero() {
            return Err(McpError::InvalidConfig("tolerances must be > 0"));
        }
        Ok(Self {
            secret,
            clock,
            nonce_generator,
            nonce_store,
            timestamp_tolerance,
            nonce_ttl,
        })
    }

    pub fn sign(
        &self,
        payload: impl Into<String>,
        sender_id: Option<&str>,
    ) -> Result<McpSignedMessage, McpError> {
        let payload = payload.into();
        let timestamp_ms = unix_ms(self.clock.now())?;
        let nonce = self.nonce_generator.generate()?;
        let signature = self.sign_fields(timestamp_ms, &nonce, sender_id, &payload)?;
        Ok(McpSignedMessage {
            payload,
            timestamp_ms,
            nonce,
            sender_id: sender_id.map(str::to_string),
            signature,
        })
    }

    pub fn verify(&self, message: &McpSignedMessage) -> Result<(), McpError> {
        let now_ms = unix_ms(self.clock.now())?;
        let now_secs = now_ms / 1000;
        self.nonce_store.cleanup(now_secs)?;
        if now_ms.abs_diff(message.timestamp_ms) > self.timestamp_tolerance.as_millis() as u64 {
            return Err(McpError::AccessDenied {
                reason: "message timestamp outside tolerance".to_string(),
            });
        }
        let provided = STANDARD
            .decode(&message.signature)
            .map_err(|_| McpError::InvalidSignature)?;
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).map_err(|_| McpError::InvalidHmacKey)?;
        let canonical = signature_input(
            message.timestamp_ms,
            &message.nonce,
            message.sender_id.as_deref(),
            &message.payload,
        );
        mac.update(canonical.as_bytes());
        mac.verify_slice(&provided)
            .map_err(|_| McpError::InvalidSignature)?;
        let expires_at_secs = now_secs
            .checked_add(self.nonce_ttl.as_secs())
            .ok_or(McpError::InvalidConfig("nonce ttl overflow"))?;
        if !self
            .nonce_store
            .reserve(message.nonce.clone(), expires_at_secs, now_secs)?
        {
            return Err(McpError::ReplayDetected);
        }
        Ok(())
    }

    fn sign_fields(
        &self,
        timestamp_ms: u64,
        nonce: &str,
        sender_id: Option<&str>,
        payload: &str,
    ) -> Result<String, McpError> {
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).map_err(|_| McpError::InvalidHmacKey)?;
        let canonical = signature_input(timestamp_ms, nonce, sender_id, payload);
        mac.update(canonical.as_bytes());
        Ok(STANDARD.encode(mac.finalize().into_bytes()))
    }
}

/// Versioned, injective canonical representation shared with the Python
/// signer (`agent_os.mcp_message_signer`, tag `mcp-sig-v2`).
///
/// Fields are length-prefixed with their UTF-8 byte length, so a separator
/// character (`|`, `:`) inside any field cannot merge two distinct field
/// tuples into the same HMAC input (#4199). `sender_id=None` and `""` share
/// the single `0:` encoding. The millisecond timestamp is placed last.
fn signature_input(timestamp_ms: u64, nonce: &str, sender_id: Option<&str>, payload: &str) -> String {
    let sender = sender_id.unwrap_or("");
    format!(
        "mcp-sig-v2|{}:{}|{}:{}|{}:{}|{}",
        nonce.len(),
        nonce,
        sender.len(),
        sender,
        payload.len(),
        payload,
        timestamp_ms
    )
}

fn unix_ms(time: SystemTime) -> Result<u64, McpError> {
    Ok(time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| McpError::AccessDenied {
            reason: "system clock before unix epoch".to_string(),
        })?
        .as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::clock::{DeterministicNonceGenerator, FixedClock};
    use std::time::SystemTime;

    fn signer_with(clock: Arc<dyn Clock>, nonces: Vec<String>) -> McpMessageSigner {
        McpMessageSigner::new(
            b"message-secret".to_vec(),
            clock,
            Arc::new(DeterministicNonceGenerator::from_values(nonces)),
            Arc::new(InMemoryNonceStore::default()),
            Duration::from_secs(60),
            Duration::from_secs(120),
        )
        .unwrap()
    }

    #[test]
    fn signs_and_verifies_messages() {
        let signer = signer_with(
            Arc::new(FixedClock::new(SystemTime::UNIX_EPOCH)),
            vec!["n1".into()],
        );
        let message = signer.sign("payload", None).unwrap();
        signer.verify(&message).unwrap();
    }

    #[test]
    fn rejects_replayed_messages() {
        let signer = signer_with(
            Arc::new(FixedClock::new(SystemTime::UNIX_EPOCH)),
            vec!["n1".into()],
        );
        let message = signer.sign("payload", None).unwrap();
        signer.verify(&message).unwrap();
        assert!(matches!(
            signer.verify(&message),
            Err(McpError::ReplayDetected)
        ));
    }

    /// Shared key/timestamp of the cross-SDK vector set. The Python SDK
    /// asserts the identical vectors (see docs/security/canonical-signing-v2.md).
    const VECTOR_SECRET: &[u8] = b"mcp-sig-v2-cross-sdk-vector-key-000001";

    fn vector_ts() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_millis(1_700_000_000_000)
    }

    fn vector_signer(nonce: &str) -> McpMessageSigner {
        McpMessageSigner::new(
            VECTOR_SECRET.to_vec(),
            Arc::new(FixedClock::new(vector_ts())),
            Arc::new(DeterministicNonceGenerator::from_values(vec![
                nonce.to_string(),
            ])),
            Arc::new(InMemoryNonceStore::default()),
            Duration::from_secs(60),
            Duration::from_secs(120),
        )
        .unwrap()
    }

    #[test]
    fn matches_python_v2_shared_vectors() {
        let cases: [(&str, Option<&str>, &str, &str); 5] = [
            (
                "n",
                None,
                "x:y",
                "39NyejcFc/+OwkXUgFZ1lKL/kBsw4tG78Hys703XO/o=",
            ),
            (
                "n:x",
                None,
                "y",
                "Y8meNY8PW2b36UjsUJi0m1meP8wnyS39dNtU56a6ATo=",
            ),
            (
                "a|b",
                Some("s|t"),
                "p|q",
                "b65/xI6FSiAfkS3W88TjSzo9wnkSIsGhi+R1Ocezbhw=",
            ),
            (
                "நி",
                None,
                "🚀 {\"json\":[1,2]}",
                "4NFaIHP94Y2o3bT+Wqk76aIf3rXZ2AxqqmVQ5I/l59g=",
            ),
            (
                "",
                Some("agent-1"),
                "hello",
                "DTfBQSd5X5lWxpqJNTyqdfVomQOrfFOUyog8kRo5RTc=",
            ),
        ];
        for (nonce, sender, payload, expected) in cases {
            let signer = vector_signer(nonce);
            let message = signer.sign(payload, sender).unwrap();
            assert_eq!(message.timestamp_ms, 1_700_000_000_000);
            assert_eq!(
                message.signature, expected,
                "vector mismatch for nonce {nonce:?}"
            );
        }
    }

    /// Regression for #4199: under the previous colon-joined encoding,
    /// (nonce "n", payload "x:y") and (nonce "n:x", payload "y") produced
    /// the identical HMAC input `{timestamp}:n:x:y`, so a field-reframed
    /// envelope verified under a fresh nonce store. The length-prefixed
    /// canonical encoding must reject it.
    #[test]
    fn rejects_signature_field_reframing() {
        let signer = vector_signer("n");
        let signed = signer.sign("x:y", None).unwrap();
        assert_eq!(
            signed.signature,
            "39NyejcFc/+OwkXUgFZ1lKL/kBsw4tG78Hys703XO/o="
        );
        let reframed = McpSignedMessage {
            payload: "y".to_string(),
            timestamp_ms: signed.timestamp_ms,
            nonce: "n:x".to_string(),
            sender_id: signed.sender_id.clone(),
            signature: signed.signature.clone(),
        };
        assert!(matches!(
            signer.verify(&reframed),
            Err(McpError::InvalidSignature)
        ));
    }

    /// Documented sender semantics: `None` and `""` share one encoding.
    #[test]
    fn none_and_empty_sender_share_one_encoding() {
        let signer = vector_signer("n");
        let without = signer.sign("payload", None).unwrap();
        let empty = signer.sign("payload", Some("")).unwrap();
        assert_eq!(without.signature, empty.signature);
    }
}

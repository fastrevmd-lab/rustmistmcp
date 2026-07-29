//! Injectable Mist dispatch contract.
//!
//! This module deliberately provides no concrete HTTP client while mecmcp#90
//! owns the shared outbound HTTPS, secret, path-expansion, and byte-boundary
//! foundations.

use async_trait::async_trait;

use crate::{MistRequest, MistResponse};

/// An injected, asynchronous dispatcher for already-validated Mist requests.
///
/// Implementations are supplied by the application. This crate does not make
/// network requests, load credentials, or retry operations at this boundary.
#[async_trait]
pub trait MistClient: Send + Sync {
    /// Execute one catalog-bound request.
    async fn execute(&self, request: MistRequest) -> Result<MistResponse, MistError>;
}

/// Deliberately unavailable default client used while mecmcp#90 is open.
///
/// This implementation performs no I/O and never loads a credential.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedMistClient;

#[async_trait]
impl MistClient for BlockedMistClient {
    async fn execute(&self, _request: MistRequest) -> Result<MistResponse, MistError> {
        Err(MistError::TransportUnavailable)
    }
}

/// Stable errors exchanged across the Mist dispatch seam.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MistError {
    /// The requested operation is not present in the audited catalog.
    #[error("unknown Mist operation: {0}")]
    UnknownOperation(String),
    /// A value conflicts with the selected operation's catalog contract.
    #[error("invalid Mist request for {operation_id}: {reason}")]
    InvalidRequest {
        /// The supplied operation ID.
        operation_id: String,
        /// A human-readable validation reason; schema-validator text is not a
        /// compatibility promise.
        reason: String,
    },
    /// A supplied response conflicts with the selected operation's catalog contract.
    #[error("invalid Mist response for {operation_id}: {reason}")]
    InvalidResponse {
        /// The supplied operation ID.
        operation_id: String,
        /// A human-readable validation reason.
        reason: String,
    },
    /// A continuation cursor is malformed or does not match its request.
    #[error("invalid Mist cursor: {0}")]
    InvalidCursor(String),
    /// A supplied client already parsed a Mist rate-limit result.
    #[error("Mist API rate-limited the request")]
    RateLimited {
        /// Parsed `Retry-After` seconds, when the shared transport supplied it.
        retry_after_secs: Option<u64>,
    },
    /// No production transport exists at this open-prerequisite seam.
    #[error("Mist client transport is unavailable")]
    TransportUnavailable,
    /// A supplied client mapped a Mist service failure.
    #[error("Mist API request failed: {0}")]
    Service(String),
}

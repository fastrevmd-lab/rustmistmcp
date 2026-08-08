//! Injectable Mist dispatch contract.

use async_trait::async_trait;
use mecmcp_secret::OutboundSecret;
use std::sync::Arc;
use tokio::sync::Semaphore;
use url::Url;

use crate::{Catalog, MistCursor, MistRequest, MistResponse, MistResponseBody};

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

/// Production HTTPS Mist client over mecmcp-http.
#[derive(Clone)]
pub struct HttpMistClient {
    http: Arc<mecmcp_http::HttpClient>,
    base_url: Url,
    credential: Arc<OutboundSecret>,
    catalog: Arc<Catalog>,
    concurrency: Arc<Semaphore>,
}

impl std::fmt::Debug for HttpMistClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpMistClient")
            .field("base_url", &self.base_url)
            .field("credential", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl HttpMistClient {
    /// Build a production HTTPS-only client.
    ///
    /// The consuming binary must install a rustls crypto provider first.
    ///
    /// # Errors
    ///
    /// Returns configuration or client-construction errors.
    pub fn new(
        endpoint: &str,
        credential: String,
        catalog: Arc<Catalog>,
        config: HttpMistClientConfig,
    ) -> Result<Self, HttpMistClientError> {
        let base_url = Url::parse(endpoint).map_err(|_| HttpMistClientError::InvalidEndpoint)?;

        if base_url.scheme() != "https" {
            return Err(HttpMistClientError::InvalidEndpoint);
        }

        if credential.is_empty() || credential.len() > 16 * 1024 {
            return Err(HttpMistClientError::InvalidCredential);
        }

        let http_config = mecmcp_http::HttpClientConfig {
            connect_timeout: config.connect_timeout,
            request_timeout: config.request_timeout,
            max_concurrent_requests: config.max_concurrency,
            max_queued_requests: config.max_concurrency * 2,
            pool_idle_timeout: std::time::Duration::from_secs(300),
            pool_max_idle_per_host: config.max_concurrency,
            user_agent: format!("rustmistmcp/{}", env!("CARGO_PKG_VERSION")),
            max_response_bytes: config.max_response_bytes,
            extra_root_certificates: vec![],
        };

        let http = mecmcp_http::HttpClient::new(http_config)
            .map_err(|_| HttpMistClientError::ClientConstruction)?;

        Ok(Self {
            http: Arc::new(http),
            base_url,
            credential: Arc::new(OutboundSecret::new_unchecked(credential)),
            catalog,
            concurrency: Arc::new(Semaphore::new(config.max_concurrency)),
        })
    }

    /// Construct an [`HttpMistClient`] from explicit parts for integration tests.
    ///
    /// Bypasses endpoint validation and HTTPS enforcement, allowing tests to use
    /// plain HTTP mock servers. Do not use in production code.
    pub fn from_test_parts(
        base_url: Url,
        credential: String,
        catalog: Arc<Catalog>,
        max_response_bytes: usize,
    ) -> Self {
        let config = HttpMistClientConfig {
            connect_timeout: std::time::Duration::from_secs(1),
            request_timeout: std::time::Duration::from_secs(2),
            max_response_bytes,
            max_concurrency: 2,
        };

        let http_config = mecmcp_http::HttpClientConfig {
            connect_timeout: config.connect_timeout,
            request_timeout: config.request_timeout,
            max_concurrent_requests: config.max_concurrency,
            max_queued_requests: config.max_concurrency * 2,
            pool_idle_timeout: std::time::Duration::from_secs(60),
            pool_max_idle_per_host: config.max_concurrency,
            user_agent: "rustmistmcp-test".to_owned(),
            max_response_bytes: config.max_response_bytes,
            extra_root_certificates: vec![],
        };

        let http = mecmcp_http::HttpClient::new(http_config).expect("test client");

        Self {
            http: Arc::new(http),
            base_url,
            credential: Arc::new(OutboundSecret::new_unchecked(credential)),
            catalog,
            concurrency: Arc::new(Semaphore::new(config.max_concurrency)),
        }
    }

    fn build_url(
        &self,
        operation_id: &str,
        path: &std::collections::BTreeMap<String, String>,
        query: &std::collections::BTreeMap<String, serde_json::Value>,
    ) -> Result<Url, MistError> {
        let operation = self
            .catalog
            .operation(operation_id)
            .ok_or_else(|| MistError::UnknownOperation(operation_id.to_owned()))?;

        let mut url = self.base_url.clone();
        let mut expanded_path = operation.path.clone();

        for (param_name, param_value) in path {
            let placeholder = format!("{{{param_name}}}");
            if !expanded_path.contains(&placeholder) {
                return Err(MistError::InvalidRequest {
                    operation_id: operation_id.to_owned(),
                    reason: format!("path parameter {param_name} not in operation path"),
                });
            }
            expanded_path = expanded_path.replace(&placeholder, param_value);
        }

        url.set_path(&expanded_path);

        // Add query parameters
        {
            let mut pairs = url.query_pairs_mut();
            for (key, value) in query {
                let value_str = match value {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    serde_json::Value::Bool(b) => b.to_string(),
                    serde_json::Value::Null => continue,
                    _ => {
                        return Err(MistError::InvalidRequest {
                            operation_id: operation_id.to_owned(),
                            reason: format!(
                                "query parameter {key} must be string, number, or bool"
                            ),
                        });
                    }
                };
                pairs.append_pair(key, &value_str);
            }
        }

        Ok(url)
    }

    fn extract_cursor_from_json(
        &self,
        json: &serde_json::Value,
        operation_id: &str,
    ) -> Option<MistCursor> {
        // Get the operation to determine pagination mode
        let operation = self.catalog.operation(operation_id)?;

        if operation.pagination == crate::catalog::PaginationMode::None {
            return None;
        }

        // Mist pagination uses different cursor field names depending on the operation
        let cursor_value = json
            .get("next")
            .or_else(|| json.get("cursor"))
            .or_else(|| json.get("page_token"))
            .or_else(|| json.get("search_after"))?;

        let cursor_str = cursor_value.as_str()?;
        if cursor_str.is_empty() {
            return None;
        }

        // Create cursor with proper pagination mode and origin
        MistCursor::new(
            operation_id.to_owned(),
            &self.base_url,
            operation.pagination,
            cursor_str.to_owned(),
        )
        .ok()
    }
}

#[async_trait]
impl MistClient for HttpMistClient {
    async fn execute(&self, request: MistRequest) -> Result<MistResponse, MistError> {
        let _permit = self.concurrency.acquire().await.expect("semaphore");

        let url = self.build_url(&request.operation_id, &request.path, &request.query)?;

        let operation = self
            .catalog
            .operation(&request.operation_id)
            .ok_or_else(|| MistError::UnknownOperation(request.operation_id.clone()))?;

        let method = match operation.method.as_str() {
            "GET" => mecmcp_http::Method::Get,
            "POST" => mecmcp_http::Method::Post,
            "PUT" => mecmcp_http::Method::Put,
            "PATCH" => mecmcp_http::Method::Patch,
            "DELETE" => mecmcp_http::Method::Delete,
            other => {
                return Err(MistError::InvalidRequest {
                    operation_id: request.operation_id.clone(),
                    reason: format!("unsupported HTTP method: {other}"),
                });
            }
        };

        let mut http_request = mecmcp_http::HttpRequest::new(method, url.as_str())
            .map_err(|_| MistError::Service("failed to build HTTP request".to_owned()))?;

        // Add Authorization header with Mist's Token scheme
        let auth_secret =
            OutboundSecret::new_unchecked(format!("Token {}", self.credential.expose()));
        http_request = http_request
            .secret_header("Authorization", &auth_secret)
            .map_err(|_| MistError::Service("failed to set auth header".to_owned()))?;

        // Add JSON body if present
        if let Some(json_body) = &request.json {
            let body_bytes = serde_json::to_vec(json_body)
                .map_err(|_| MistError::Service("failed to serialize request body".to_owned()))?;
            http_request = http_request.body(body_bytes);
        }

        // Execute the request
        let http_response = self
            .http
            .send(http_request)
            .await
            .map_err(|error| MistError::Service(format!("HTTP request failed: {error}")))?;

        let status = http_response.status();

        // Check for rate limiting
        if status == 429 {
            let retry_after = http_response
                .header_str("Retry-After")
                .and_then(|s| s.parse::<u64>().ok());
            return Err(MistError::RateLimited {
                retry_after_secs: retry_after,
            });
        }

        // Get response body
        let body_bytes = http_response.body().to_vec();
        let body = if body_bytes.is_empty() {
            MistResponseBody::Empty
        } else {
            // Try to parse as JSON
            match serde_json::from_slice(&body_bytes) {
                Ok(json) => MistResponseBody::Json(json),
                Err(_) => {
                    // Try as UTF-8 text
                    match String::from_utf8(body_bytes.clone()) {
                        Ok(text) => MistResponseBody::Text(text),
                        Err(_) => MistResponseBody::Binary(body_bytes),
                    }
                }
            }
        };

        // Extract cursor from response if present
        let cursor = if let MistResponseBody::Json(ref json) = body {
            self.extract_cursor_from_json(json, &request.operation_id)
        } else {
            None
        };

        Ok(MistResponse {
            operation_id: request.operation_id,
            status,
            body,
            cursor,
        })
    }
}

/// Configuration for the HTTP Mist client.
#[derive(Clone, Debug)]
pub struct HttpMistClientConfig {
    /// TCP connect timeout.
    pub connect_timeout: std::time::Duration,
    /// Whole-request deadline.
    pub request_timeout: std::time::Duration,
    /// Maximum response body bytes.
    pub max_response_bytes: usize,
    /// Maximum concurrent requests.
    pub max_concurrency: usize,
}

impl Default for HttpMistClientConfig {
    fn default() -> Self {
        Self {
            connect_timeout: std::time::Duration::from_secs(10),
            request_timeout: std::time::Duration::from_secs(30),
            max_response_bytes: 10 * 1024 * 1024,
            max_concurrency: 8,
        }
    }
}

/// Errors from HTTP client construction.
#[derive(Debug, thiserror::Error)]
pub enum HttpMistClientError {
    /// The endpoint URL is invalid or not HTTPS.
    #[error("invalid Mist endpoint URL")]
    InvalidEndpoint,
    /// The credential is empty or too large.
    #[error("invalid Mist credential")]
    InvalidCredential,
    /// Failed to construct the HTTP client.
    #[error("failed to construct HTTP client")]
    ClientConstruction,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    const TEST_TOKEN: &str = "test-token-12345";
    const ORG_ID: &str = "11111111-1111-1111-1111-111111111111";

    fn test_catalog() -> Arc<Catalog> {
        Arc::new(Catalog::embedded().expect("embedded catalog"))
    }

    #[test]
    fn http_client_construction_validates_endpoint() {
        let catalog = test_catalog();

        // HTTP URLs are rejected
        let http_result = HttpMistClient::new(
            "http://api.mist.com/",
            TEST_TOKEN.to_owned(),
            catalog.clone(),
            HttpMistClientConfig::default(),
        );
        assert!(matches!(
            http_result,
            Err(HttpMistClientError::InvalidEndpoint)
        ));

        // HTTPS URLs are accepted
        let https_result = HttpMistClient::new(
            "https://api.mist.com/",
            TEST_TOKEN.to_owned(),
            catalog,
            HttpMistClientConfig::default(),
        );
        assert!(https_result.is_ok());
    }

    #[test]
    fn http_client_rejects_invalid_credentials() {
        let catalog = test_catalog();

        // Empty credential
        let empty_result = HttpMistClient::new(
            "https://api.mist.com/",
            String::new(),
            catalog.clone(),
            HttpMistClientConfig::default(),
        );
        assert!(matches!(
            empty_result,
            Err(HttpMistClientError::InvalidCredential)
        ));

        // Oversized credential (> 16KB)
        let large_cred = "x".repeat(17 * 1024);
        let large_result = HttpMistClient::new(
            "https://api.mist.com/",
            large_cred,
            catalog,
            HttpMistClientConfig::default(),
        );
        assert!(matches!(
            large_result,
            Err(HttpMistClientError::InvalidCredential)
        ));
    }

    #[test]
    fn http_client_builds_correct_url_with_path_parameters() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let client = HttpMistClient::from_test_parts(
            Url::parse("https://api.mist.com/").expect("url"),
            TEST_TOKEN.to_owned(),
            test_catalog(),
            1024 * 1024,
        );

        let path = BTreeMap::from([("org_id".to_owned(), ORG_ID.to_owned())]);
        let query = BTreeMap::new();

        let url = client
            .build_url("getOrg", &path, &query)
            .expect("build URL");
        assert_eq!(url.path(), format!("/api/v1/orgs/{ORG_ID}"));
    }

    #[test]
    fn http_client_builds_url_with_query_parameters() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let client = HttpMistClient::from_test_parts(
            Url::parse("https://api.mist.com/").expect("url"),
            TEST_TOKEN.to_owned(),
            test_catalog(),
            1024 * 1024,
        );

        let path = BTreeMap::from([("org_id".to_owned(), ORG_ID.to_owned())]);
        let mut query = BTreeMap::new();
        query.insert("limit".to_owned(), serde_json::json!(100));
        query.insert("page".to_owned(), serde_json::json!(2));

        let url = client
            .build_url("listOrgSites", &path, &query)
            .expect("build URL");
        let query_str = url.query().expect("query string");
        assert!(query_str.contains("limit=100"));
        assert!(query_str.contains("page=2"));
    }

    #[test]
    fn http_client_extracts_cursor_from_json_response() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let client = HttpMistClient::from_test_parts(
            Url::parse("https://api.mist.com/").expect("url"),
            TEST_TOKEN.to_owned(),
            test_catalog(),
            1024 * 1024,
        );

        let json_with_cursor = serde_json::json!({
            "results": [],
            "next": "cursor-token-123"
        });

        let cursor = client.extract_cursor_from_json(&json_with_cursor, "listOrgSites");
        assert!(cursor.is_some());
    }

    #[test]
    fn http_client_does_not_extract_cursor_from_non_paginated_operation() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let client = HttpMistClient::from_test_parts(
            Url::parse("https://api.mist.com/").expect("url"),
            TEST_TOKEN.to_owned(),
            test_catalog(),
            1024 * 1024,
        );

        let json_with_cursor = serde_json::json!({
            "id": ORG_ID,
            "next": "cursor-token-123"
        });

        // getOrg is not paginated
        let cursor = client.extract_cursor_from_json(&json_with_cursor, "getOrg");
        assert!(cursor.is_none());
    }
}

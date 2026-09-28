//! Injectable Mist dispatch contract.

use async_trait::async_trait;
use mecmcp_secret::OutboundSecret;
use std::sync::Arc;
use tokio::sync::Semaphore;
use url::Url;

use crate::catalog::PaginationMode;
use crate::{Catalog, MistCursor, MistPageInfo, MistRequest, MistResponse, MistResponseBody};

/// An injected, asynchronous dispatcher for already-validated Mist requests.
///
/// Implementations are supplied by the application. This crate does not make
/// network requests, load credentials, or retry operations at this boundary.
#[async_trait]
pub trait MistClient: Send + Sync {
    /// Execute one catalog-bound request.
    async fn execute(&self, request: MistRequest) -> Result<MistResponse, MistError>;

    /// Whether this transport refuses everything without touching the network.
    ///
    /// Exists so the production constructor's choice of client is assertable
    /// without a live tenant. The endpoint allowlist only admits real Mist
    /// regions, so "point it at an unreachable host and inspect the error" is
    /// not available, and a test that builds its own client cannot see the
    /// wiring at all — which is how `from_config` shipped returning the stub.
    fn is_blocked(&self) -> bool {
        false
    }
}

/// Deliberately unavailable client used where no Mist transport should exist.
///
/// It was the default while `mecmcp#90` was open. That foundation has landed
/// and `MistHandler::from_config` now builds a real `HttpMistClient`, so this
/// remains only for tests and for handlers constructed without a credential:
/// it performs no I/O and never loads one.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedMistClient;

#[async_trait]
impl MistClient for BlockedMistClient {
    fn is_blocked(&self) -> bool {
        true
    }

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
    ///
    /// Gated behind `test-util` rather than compiled unconditionally: this was
    /// `pub` with no gate at all, so every normal build -- including a release
    /// binary -- shipped a constructor that skips both checks
    /// [`HttpMistClient::new`] enforces. A consumer's integration tests enable
    /// the feature in their own `[dev-dependencies]` entry for this crate.
    #[cfg(any(test, feature = "test-util"))]
    pub fn from_test_parts(
        base_url: Url,
        credential: String,
        catalog: Arc<Catalog>,
        max_response_bytes: usize,
    ) -> Self {
        Self::from_test_parts_with_roots(base_url, credential, catalog, max_response_bytes, vec![])
    }

    /// As [`Self::from_test_parts`], additionally trusting `extra_root_certificates`.
    ///
    /// `mecmcp-http` refuses any outbound scheme but `https` (there is no
    /// plaintext escape hatch), so a mock server that proves real wire
    /// behavior needs a certificate the client is told to trust rather than a
    /// plain HTTP listener. Each certificate is PEM-encoded.
    #[cfg(any(test, feature = "test-util"))]
    pub fn from_test_parts_with_roots(
        base_url: Url,
        credential: String,
        catalog: Arc<Catalog>,
        max_response_bytes: usize,
        extra_root_certificates: Vec<String>,
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
            extra_root_certificates,
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

    /// The query parameter Mist expects a continuation value written back to,
    /// keyed by the pagination shape declared in the catalog.
    fn cursor_query_key(mode: PaginationMode) -> Option<&'static str> {
        match mode {
            PaginationMode::SearchAfter => Some("search_after"),
            PaginationMode::PageLimit => Some("page"),
            PaginationMode::None => None,
        }
    }

    fn build_url(
        &self,
        operation_id: &str,
        path: &std::collections::BTreeMap<String, String>,
        query: &std::collections::BTreeMap<String, serde_json::Value>,
        cursor: Option<&MistCursor>,
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

        // A continuation replaces whatever page/search_after value the stored
        // request context carried forward, so it is merged into the query map
        // before encoding rather than appended: appending would send both the
        // stale and the fresh value as duplicate query parameters.
        let mut effective_query = query.clone();
        if let Some(cursor) = cursor {
            let key = Self::cursor_query_key(cursor.mode()).ok_or_else(|| {
                MistError::InvalidCursor("cursor pagination mode must not be none".to_owned())
            })?;
            effective_query.insert(
                key.to_owned(),
                serde_json::Value::String(cursor.value().to_owned()),
            );
        }

        // Add query parameters
        {
            let mut pairs = url.query_pairs_mut();
            for (key, value) in &effective_query {
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

    /// Parse the `X-Page-Page`, `X-Page-Limit`, and `X-Page-Total` response
    /// headers Mist's `page`/`limit` endpoints use to report pagination state.
    ///
    /// Those endpoints return a bare JSON array as the body (see
    /// `listOrgSites`), so the headers are the only place this state appears.
    fn parse_page_info(response: &mecmcp_http::HttpResponse) -> Option<MistPageInfo> {
        let info = MistPageInfo {
            page: response
                .header_str("X-Page-Page")
                .and_then(|value| value.parse().ok()),
            limit: response
                .header_str("X-Page-Limit")
                .and_then(|value| value.parse().ok()),
            total: response
                .header_str("X-Page-Total")
                .and_then(|value| value.parse().ok()),
        };
        if info.is_empty() { None } else { Some(info) }
    }

    /// Extract the `search_after` value Mist embeds in the `next` URL of a
    /// search-style response body.
    ///
    /// Mist's search-after endpoints (for example `searchOrgAlarms`) do not
    /// return the continuation value as its own body field; they return a
    /// `next` field holding a full (or origin-relative) URL for the next page,
    /// and the `search_after` query parameter inside that URL is the only part
    /// of it that changes between pages.
    fn extract_search_after_cursor(
        &self,
        json: &serde_json::Value,
        operation_id: &str,
    ) -> Option<MistCursor> {
        let next = json.get("next")?.as_str()?;
        if next.is_empty() {
            return None;
        }
        let next_url = self.base_url.join(next).ok()?;
        let search_after = next_url
            .query_pairs()
            .find(|(key, _)| key == "search_after")?
            .1
            .into_owned();
        if search_after.is_empty() {
            return None;
        }
        MistCursor::new(
            operation_id.to_owned(),
            &self.base_url,
            PaginationMode::SearchAfter,
            search_after,
        )
        .ok()
    }

    /// Derive the continuation cursor for a response, per the operation's
    /// declared pagination shape.
    fn derive_next_cursor(
        &self,
        operation_id: &str,
        body: &MistResponseBody,
        page: Option<&MistPageInfo>,
    ) -> Option<MistCursor> {
        let operation = self.catalog.operation(operation_id)?;
        match operation.pagination {
            PaginationMode::None => None,
            PaginationMode::SearchAfter => {
                let MistResponseBody::Json(json) = body else {
                    return None;
                };
                self.extract_search_after_cursor(json, operation_id)
            }
            PaginationMode::PageLimit => {
                let page = page?;
                let (current_page, limit, total) = (page.page?, page.limit?, page.total?);
                if current_page.saturating_mul(limit) >= total {
                    return None;
                }
                MistCursor::new(
                    operation_id.to_owned(),
                    &self.base_url,
                    PaginationMode::PageLimit,
                    (current_page + 1).to_string(),
                )
                .ok()
            }
        }
    }
}

#[async_trait]
impl MistClient for HttpMistClient {
    async fn execute(&self, request: MistRequest) -> Result<MistResponse, MistError> {
        let _permit = self.concurrency.acquire().await.expect("semaphore");

        let url = self.build_url(
            &request.operation_id,
            &request.path,
            &request.query,
            request.cursor.as_ref(),
        )?;

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

        let page = Self::parse_page_info(&http_response);
        let cursor = self.derive_next_cursor(&request.operation_id, &body, page.as_ref());

        Ok(MistResponse {
            operation_id: request.operation_id,
            status,
            body,
            cursor,
            page,
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
            .build_url("getOrg", &path, &query, None)
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
            .build_url("listOrgSites", &path, &query, None)
            .expect("build URL");
        let query_str = url.query().expect("query string");
        assert!(query_str.contains("limit=100"));
        assert!(query_str.contains("page=2"));
    }

    #[test]
    fn build_url_threads_the_cursor_value_into_the_next_request() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let client = HttpMistClient::from_test_parts(
            Url::parse("https://api.mist.com/").expect("url"),
            TEST_TOKEN.to_owned(),
            test_catalog(),
            1024 * 1024,
        );

        let path = BTreeMap::from([("org_id".to_owned(), ORG_ID.to_owned())]);
        // The stored request context still carries page 1's own query values;
        // the cursor for page 2 must override rather than duplicate them.
        let mut query = BTreeMap::new();
        query.insert("limit".to_owned(), serde_json::json!(10));
        query.insert("page".to_owned(), serde_json::json!(1));

        let cursor = MistCursor::new(
            "listOrgSites".to_owned(),
            &Url::parse("https://api.mist.com/").expect("origin"),
            PaginationMode::PageLimit,
            "2".to_owned(),
        )
        .expect("cursor");

        let url = client
            .build_url("listOrgSites", &path, &query, Some(&cursor))
            .expect("build URL");
        let query_str = url.query().expect("query string");
        assert!(query_str.contains("page=2"), "{query_str}");
        assert!(!query_str.contains("page=1"), "{query_str}");
        assert_eq!(query_str.matches("page=").count(), 1, "{query_str}");
    }

    #[test]
    fn derive_next_cursor_extracts_search_after_from_the_next_url() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let client = HttpMistClient::from_test_parts(
            Url::parse("https://api.mist.com/").expect("url"),
            TEST_TOKEN.to_owned(),
            test_catalog(),
            1024 * 1024,
        );

        // Mirrors the real Mist response shape: `next` is a relative URL, and
        // `search_after` is the only part of it that changes between pages.
        let body = MistResponseBody::Json(serde_json::json!({
            "start": 0,
            "end": 0,
            "limit": 10,
            "total": 25,
            "results": [],
            "next": format!(
                "/api/v1/orgs/{ORG_ID}/alarms/search?limit=10&search_after=%5B123%2C+%22abc%22%5D"
            ),
        }));

        let cursor = client
            .derive_next_cursor("searchOrgAlarms", &body, None)
            .expect("cursor");
        assert_eq!(cursor.value(), "[123, \"abc\"]");
        assert_eq!(cursor.mode(), PaginationMode::SearchAfter);
    }

    #[test]
    fn derive_next_cursor_is_none_for_non_paginated_operations() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let client = HttpMistClient::from_test_parts(
            Url::parse("https://api.mist.com/").expect("url"),
            TEST_TOKEN.to_owned(),
            test_catalog(),
            1024 * 1024,
        );

        let body = MistResponseBody::Json(serde_json::json!({
            "id": ORG_ID,
            "next": "cursor-token-123"
        }));

        // getOrg is not paginated
        assert!(client.derive_next_cursor("getOrg", &body, None).is_none());
    }

    #[test]
    fn derive_next_cursor_advances_page_limit_operations_from_headers() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let client = HttpMistClient::from_test_parts(
            Url::parse("https://api.mist.com/").expect("url"),
            TEST_TOKEN.to_owned(),
            test_catalog(),
            1024 * 1024,
        );

        // listOrgSites returns a bare array; the only pagination signal is
        // the X-Page-* headers.
        let body = MistResponseBody::Json(serde_json::json!([]));

        let more_pages = MistPageInfo {
            page: Some(1),
            limit: Some(10),
            total: Some(25),
        };
        let cursor = client
            .derive_next_cursor("listOrgSites", &body, Some(&more_pages))
            .expect("cursor for remaining pages");
        assert_eq!(cursor.value(), "2");
        assert_eq!(cursor.mode(), PaginationMode::PageLimit);

        let last_page = MistPageInfo {
            page: Some(3),
            limit: Some(10),
            total: Some(25),
        };
        assert!(
            client
                .derive_next_cursor("listOrgSites", &body, Some(&last_page))
                .is_none(),
            "page 3 * limit 10 already covers all 25 results"
        );
    }
}

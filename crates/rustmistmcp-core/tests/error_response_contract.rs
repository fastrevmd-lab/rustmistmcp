//! HTTP-level proof that a 410 response is surfaced as "endpoint retired",
//! not a generic HTTP or parse failure.
//!
//! The Mist vendor retires endpoints outright (HTTP 410) rather than
//! deprecating them in place, so a caller hitting a 410 needs a clear signal
//! that the operation needs a replacement rather than a retry (MEC-410).
//! Mirrors `pagination_contract.rs`'s TLS mock-server setup: `mecmcp-http`
//! refuses plain HTTP for every outbound request, so proving this over the
//! wire means standing up a real TLS mock server rather than a plaintext one.

use std::collections::BTreeMap;
use std::sync::Arc;

use rustmistmcp_core::{Catalog, MistClient, MistError, MistRequest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ORG_ID: &str = "11111111-1111-1111-1111-111111111111";

fn tls_material() -> (String, rustls::ServerConfig) {
    let key_pair = rcgen::KeyPair::generate().expect("key pair");
    let params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).expect("cert params");
    let cert = params.self_signed(&key_pair).expect("self-signed cert");

    let cert_pem = cert.pem();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into();

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key_der)
        .expect("server cert");
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    (cert_pem, server_config)
}

async fn read_request_line<S>(stream: &mut S) -> String
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut seen = Vec::new();
    let mut byte = [0u8; 1];
    while stream.read_exact(&mut byte).await.is_ok() {
        seen.push(byte[0]);
        if seen.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8_lossy(&seen);
    head.lines().next().unwrap_or_default().to_owned()
}

fn serve_once(
    listener: tokio::net::TcpListener,
    server_config: rustls::ServerConfig,
    response: String,
) {
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut tls) = acceptor.accept(stream).await else {
            return;
        };
        let _ = read_request_line(&mut tls).await;
        let _ = tls.write_all(response.as_bytes()).await;
        let _ = tls.flush().await;
    });
}

async fn bind_local() -> (tokio::net::TcpListener, u16) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock TLS listener");
    let port = listener.local_addr().expect("local addr").port();
    (listener, port)
}

fn ensure_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn test_client(cert_pem: String, port: u16) -> Arc<rustmistmcp_core::HttpMistClient> {
    ensure_crypto_provider();
    Arc::new(
        rustmistmcp_core::HttpMistClient::from_test_parts_with_roots(
            url::Url::parse(&format!("https://localhost:{port}/")).expect("parse mock base URL"),
            "test-mist-token-12345".to_owned(),
            Arc::new(Catalog::embedded().expect("embedded catalog")),
            1024 * 1024,
            vec![cert_pem],
        ),
    )
}

#[tokio::test]
async fn retired_endpoint_returns_a_clear_endpoint_retired_error() {
    let (cert_pem, server_config) = tls_material();
    let (listener, port) = bind_local().await;

    let body = serde_json::json!({"detail": "This API has been retired"}).to_string();
    let response = format!(
        "HTTP/1.1 410 Gone\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    serve_once(listener, server_config, response);

    let client = test_client(cert_pem, port);

    let path = BTreeMap::from([("org_id".to_owned(), ORG_ID.to_owned())]);
    let result = client
        .execute(MistRequest {
            operation_id: "listOrgSites".to_owned(),
            path,
            query: BTreeMap::new(),
            json: None,
            cursor: None,
        })
        .await;

    assert_eq!(
        result,
        Err(MistError::EndpointRetired {
            operation_id: "listOrgSites".to_owned(),
        }),
        "a 410 response must map to EndpointRetired, not a generic parse/HTTP error, got: {result:?}"
    );
}

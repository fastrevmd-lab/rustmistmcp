//! HTTP-level proof that a continuation cursor advances the Mist request
//! instead of re-fetching page 1.
//!
//! `HttpMistClient::build_url` used to ignore `MistRequest::cursor` entirely,
//! so handing back the cursor from a first response and asking for "the next
//! page" silently repeated the first request. `mecmcp-http` refuses plain
//! HTTP for every outbound request (`HttpRequest::new` rejects any scheme but
//! `https`), so proving this over the wire means standing up a real TLS mock
//! server rather than a plaintext one; the certificate and TLS-acceptor setup
//! below mirrors `mecmcp-http`'s own test harness for the same reason.
//!
//! Two pagination shapes are exercised end to end against that mock server:
//! `page`/`limit` (`listOrgSites`, state carried entirely in `X-Page-*`
//! response headers) and `search_after` (`searchOrgAlarms`, state carried in
//! the response body's `next` URL).

use std::sync::Arc;
use std::{collections::BTreeMap, sync::atomic::AtomicUsize, sync::atomic::Ordering};

use rustmistmcp_core::{Catalog, MistClient, MistRequest, MistResponseBody};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ORG_ID: &str = "11111111-1111-1111-1111-111111111111";

/// Generate a self-signed `localhost` certificate and a matching TLS server config.
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

/// Read one HTTP request's start line off a TLS stream, discarding headers.
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

/// Serve `connections` TLS requests on `listener`, replying with whatever
/// `respond` computes from each request's start line (e.g. `GET
/// /api/v1/...?page=2 HTTP/1.1`).
fn serve(
    listener: tokio::net::TcpListener,
    server_config: rustls::ServerConfig,
    connections: usize,
    respond: impl Fn(&str) -> String + Send + Sync + 'static,
) {
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let respond = Arc::new(respond);
    tokio::spawn(async move {
        for _ in 0..connections {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let respond = respond.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let request_line = read_request_line(&mut tls).await;
                let response = respond(&request_line);
                let _ = tls.write_all(response.as_bytes()).await;
                let _ = tls.flush().await;
            });
        }
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

/// `headers`, when non-empty, must end in its own `\r\n` per header line: the
/// template supplies only the single blank-line terminator after it, since
/// `Connection: close\r\n` already ends that preceding header line.
fn json_response(status: &str, headers: &str, body: &serde_json::Value) -> String {
    let body = body.to_string();
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
        body.len()
    )
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
async fn page_limit_cursor_advances_to_a_distinct_second_page() {
    let (cert_pem, server_config) = tls_material();
    let (listener, port) = bind_local().await;

    serve(listener, server_config, 2, |request_line| {
        let page_2 = request_line.contains("page=2");
        let (page, site_id) = if page_2 {
            (2, "page-2-site")
        } else {
            (1, "page-1-site")
        };
        let headers = format!("X-Page-Page: {page}\r\nX-Page-Limit: 1\r\nX-Page-Total: 2\r\n");
        json_response(
            "200 OK",
            &headers,
            &serde_json::json!([{"id": site_id, "name": site_id}]),
        )
    });

    let client = test_client(cert_pem, port);

    let path = BTreeMap::from([("org_id".to_owned(), ORG_ID.to_owned())]);
    let mut query = BTreeMap::new();
    query.insert("limit".to_owned(), serde_json::json!(1));

    let first = client
        .execute(MistRequest {
            operation_id: "listOrgSites".to_owned(),
            path: path.clone(),
            query: query.clone(),
            json: None,
            cursor: None,
        })
        .await
        .expect("first page request");

    let MistResponseBody::Json(first_body) = &first.body else {
        panic!("expected JSON body");
    };
    assert_eq!(first_body[0]["id"], "page-1-site");

    let page_info = first.page.expect("X-Page-* headers parsed");
    assert_eq!(page_info.page, Some(1));
    assert_eq!(page_info.limit, Some(1));
    assert_eq!(page_info.total, Some(2));

    let cursor = first
        .cursor
        .clone()
        .expect("more pages remain, so a continuation cursor is returned");
    assert_eq!(cursor.value(), "2");

    // Mirrors what the server layer does: the stored request context (path,
    // query) from the first call is replayed verbatim, with only the cursor
    // supplying the advance to page 2.
    let second = client
        .execute(MistRequest {
            operation_id: "listOrgSites".to_owned(),
            path,
            query,
            json: None,
            cursor: Some(cursor),
        })
        .await
        .expect("second page request");

    let MistResponseBody::Json(second_body) = &second.body else {
        panic!("expected JSON body");
    };
    assert_eq!(
        second_body[0]["id"], "page-2-site",
        "the second request must fetch page 2, not repeat page 1"
    );
    assert_ne!(
        first_body, second_body,
        "second page must return data distinct from the first page"
    );

    let second_page_info = second.page.expect("X-Page-* headers parsed");
    assert_eq!(second_page_info.page, Some(2));
    // Page 2 of 2 at limit 1 is the last page: no further cursor.
    assert!(second.cursor.is_none());
}

#[tokio::test]
async fn search_after_cursor_advances_to_a_distinct_second_page() {
    let (cert_pem, server_config) = tls_material();
    let (listener, port) = bind_local().await;
    let request_count = Arc::new(AtomicUsize::new(0));

    {
        let request_count = request_count.clone();
        serve(listener, server_config, 2, move |request_line| {
            let has_search_after = request_line.contains("search_after=");
            request_count.fetch_add(1, Ordering::SeqCst);
            let (alarm_id, next) = if has_search_after {
                ("alarm-2", serde_json::Value::Null)
            } else {
                (
                    "alarm-1",
                    serde_json::Value::String(format!(
                        "/api/v1/orgs/{ORG_ID}/alarms/search?limit=1&search_after=%5B2%2C+%22alarm-2%22%5D"
                    )),
                )
            };
            let mut body = serde_json::json!({
                "start": 0,
                "end": 0,
                "limit": 1,
                "total": 2,
                "results": [{"id": alarm_id}],
            });
            if !next.is_null() {
                body["next"] = next;
            }
            json_response("200 OK", "", &body)
        });
    }

    let client = test_client(cert_pem, port);

    let path = BTreeMap::from([("org_id".to_owned(), ORG_ID.to_owned())]);
    let mut query = BTreeMap::new();
    query.insert("limit".to_owned(), serde_json::json!(1));

    let first = client
        .execute(MistRequest {
            operation_id: "searchOrgAlarms".to_owned(),
            path: path.clone(),
            query: query.clone(),
            json: None,
            cursor: None,
        })
        .await
        .expect("first page request");

    let MistResponseBody::Json(first_body) = &first.body else {
        panic!("expected JSON body");
    };
    assert_eq!(first_body["results"][0]["id"], "alarm-1");

    let cursor = first
        .cursor
        .clone()
        .expect("a next URL was present, so a continuation cursor is returned");
    assert_eq!(cursor.value(), "[2, \"alarm-2\"]");

    let second = client
        .execute(MistRequest {
            operation_id: "searchOrgAlarms".to_owned(),
            path,
            query,
            json: None,
            cursor: Some(cursor),
        })
        .await
        .expect("second page request");

    let MistResponseBody::Json(second_body) = &second.body else {
        panic!("expected JSON body");
    };
    assert_eq!(
        second_body["results"][0]["id"], "alarm-2",
        "the second request must advance search_after, not repeat page 1"
    );
    assert_ne!(
        first_body, second_body,
        "second page must return data distinct from the first page"
    );
    assert!(
        second.cursor.is_none(),
        "the mock server signals end of results by omitting `next`"
    );
    assert_eq!(request_count.load(Ordering::SeqCst), 2);
}

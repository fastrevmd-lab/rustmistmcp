//! Startup and periodic discovery of the org → site map.
//!
//! `MistHandler` refuses every site-scoped tool call for a site it does not
//! already know (see `MistHandler::replace_sites`), so whoever constructs it
//! must supply a populated map. This walks `listOrgSites` for each
//! allowlisted org to build that map, and offers a background loop to keep
//! it current so newly added or removed sites are picked up without a
//! restart.

use std::collections::BTreeMap;
use std::time::Duration;

use rustmistmcp_core::{Catalog, MistClient, MistError, MistRequest, MistResponseBody, MistTarget};
use url::Url;

use crate::MistHandler;

const LIST_ORG_SITES_OPERATION: &str = "listOrgSites";
const PAGE_LIMIT: u64 = 100;

/// Bounds the number of pages fetched for a single org in a single pass.
///
/// Mist declares no ceiling on page count; this stops a misbehaving or
/// malicious API from making discovery loop forever. At `PAGE_LIMIT` sites
/// per page this is generous headroom over the 4096-site total the handler
/// tracks (see [`MAX_TOTAL_SITES`]).
const MAX_PAGES_PER_ORG: u64 = 64;

/// Matches the ceiling `MistHandler` enforces on the assembled site map.
/// Stopping discovery here means a tenant beyond it degrades to "fewer
/// sites known" instead of the whole map being rejected once handed to
/// [`MistHandler::replace_sites`].
const MAX_TOTAL_SITES: usize = 4096;

/// Failure discovering one organization's sites.
#[derive(Debug, thiserror::Error)]
enum OrgDiscoveryError {
    /// Building or dispatching the `listOrgSites` request failed.
    #[error(transparent)]
    Mist(#[from] MistError),
    /// Mist returned a non-2xx status for `listOrgSites`.
    #[error("listOrgSites returned HTTP {0}")]
    Status(u16),
    /// The validated response body was not the declared JSON array.
    #[error("listOrgSites response was not a JSON array")]
    NotAnArray,
}

/// Discover every site in each allowlisted org.
///
/// Best-effort per organization: a request failure, rate limit, or malformed
/// response for one org is logged and that org is skipped rather than
/// aborting the whole pass, so one flaky tenant does not blank out sites
/// already known for the rest. A site that fails discovery this pass simply
/// stays (or remains) unknown to `MistHandler`, which is the fail-closed
/// outcome: calls against an unknown site are refused, never guessed at.
pub async fn discover_sites(
    client: &dyn MistClient,
    catalog: &Catalog,
    origin: &Url,
    allowed_orgs: &[String],
) -> BTreeMap<String, String> {
    let mut sites = BTreeMap::new();
    for org_id in allowed_orgs {
        if let Err(error) = discover_org_sites(client, catalog, origin, org_id, &mut sites).await {
            tracing::error!(
                org_id = %org_id,
                %error,
                "site discovery failed for organization; its sites remain unknown until the next refresh"
            );
        }
        if sites.len() > MAX_TOTAL_SITES {
            tracing::error!(
                total = sites.len(),
                limit = MAX_TOTAL_SITES,
                "site discovery exceeded the maximum tracked site count; stopping early"
            );
            break;
        }
    }
    sites
}

async fn discover_org_sites(
    client: &dyn MistClient,
    catalog: &Catalog,
    origin: &Url,
    org_id: &str,
    sites: &mut BTreeMap<String, String>,
) -> Result<(), OrgDiscoveryError> {
    for page in 1..=MAX_PAGES_PER_ORG {
        let request = MistRequest {
            operation_id: LIST_ORG_SITES_OPERATION.to_owned(),
            path: BTreeMap::from([("org_id".to_owned(), org_id.to_owned())]),
            query: BTreeMap::from([
                ("limit".to_owned(), serde_json::json!(PAGE_LIMIT)),
                ("page".to_owned(), serde_json::json!(page)),
            ]),
            json: None,
            cursor: None,
        };
        let request = request.validate(catalog, origin)?;
        let response = client.execute(request).await?;
        if response.operation_id != LIST_ORG_SITES_OPERATION {
            return Err(MistError::InvalidResponse {
                operation_id: LIST_ORG_SITES_OPERATION.to_owned(),
                reason: "response operation does not match request operation".to_owned(),
            }
            .into());
        }
        let response = response.validate(catalog, origin)?;
        if !(200..300).contains(&response.status) {
            return Err(OrgDiscoveryError::Status(response.status));
        }
        let MistResponseBody::Json(serde_json::Value::Array(page_sites)) = &response.body else {
            return Err(OrgDiscoveryError::NotAnArray);
        };
        let page_len = page_sites.len();
        for site in page_sites {
            let Some(site_id) = site.get("id").and_then(serde_json::Value::as_str) else {
                tracing::warn!(
                    org_id = %org_id,
                    "listOrgSites entry has no string id; skipping"
                );
                continue;
            };
            if MistTarget::site(site_id).is_err() {
                tracing::warn!(
                    org_id = %org_id,
                    "listOrgSites entry has a non-canonical id; skipping"
                );
                continue;
            }
            sites.insert(site_id.to_owned(), org_id.to_owned());
        }
        if (page_len as u64) < PAGE_LIMIT {
            break;
        }
    }
    Ok(())
}

/// Spawn a background task that re-discovers the site map on `interval` and
/// swaps it into `handler`.
///
/// A discovered map that fails [`MistHandler::replace_sites`]'s validation
/// (for example a response naming an org outside the allowlist) is logged
/// and dropped; the previous map stays in force rather than the refresh
/// tearing down what already worked.
///
/// Returns the task's join handle so a caller can abort it on shutdown
/// instead of leaving it running past the point anything observes it.
pub fn spawn_refresh_loop(handler: MistHandler, interval: Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // The first tick fires immediately; startup already discovered once.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let sites = discover_sites(
                handler.client().as_ref(),
                handler.catalog(),
                handler.origin(),
                handler.allowed_orgs(),
            )
            .await;
            let discovered = sites.len();
            match handler.replace_sites(sites) {
                Ok(()) => {
                    tracing::info!(sites = discovered, "refreshed Mist site map");
                }
                Err(error) => {
                    tracing::error!(
                        %error,
                        "discovered site map failed validation; keeping the previous map"
                    );
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use rustmistmcp_core::{Catalog, MistResponse};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn site_json(id: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "name": "test-site",
            "country_code": "US",
            "timezone": "UTC",
            "created_time": 0,
        })
    }

    /// Serves `pages` (already split as Mist would return them) for one org,
    /// keyed by `(org_id, page)`; anything else is a test bug.
    struct PagedClient {
        pages: BTreeMap<(String, u64), Vec<serde_json::Value>>,
        calls: AtomicUsize,
        fail_org: Option<String>,
    }

    #[async_trait]
    impl MistClient for PagedClient {
        async fn execute(&self, request: MistRequest) -> Result<MistResponse, MistError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let org_id = request.path.get("org_id").cloned().unwrap_or_default();
            if self.fail_org.as_deref() == Some(org_id.as_str()) {
                return Err(MistError::Service("simulated failure".to_owned()));
            }
            let page = request
                .query
                .get("page")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(1);
            let sites = self.pages.get(&(org_id, page)).cloned().unwrap_or_default();
            Ok(MistResponse {
                operation_id: LIST_ORG_SITES_OPERATION.to_owned(),
                status: 200,
                body: MistResponseBody::Json(serde_json::Value::Array(sites)),
                cursor: None,
            })
        }
    }

    fn origin() -> Url {
        Url::parse("https://api.mist.com/").expect("origin")
    }

    #[tokio::test(flavor = "current_thread")]
    async fn empty_org_list_discovers_nothing() {
        let catalog = Catalog::embedded().expect("catalog");
        let client = PagedClient {
            pages: BTreeMap::new(),
            calls: AtomicUsize::new(0),
            fail_org: None,
        };
        let sites = discover_sites(&client, &catalog, &origin(), &[]).await;
        assert!(sites.is_empty());
        assert_eq!(client.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn org_with_zero_sites_contributes_nothing() {
        let catalog = Catalog::embedded().expect("catalog");
        let org_id = "11111111-1111-1111-1111-111111111111".to_owned();
        let client = PagedClient {
            pages: BTreeMap::from([((org_id.clone(), 1), vec![])]),
            calls: AtomicUsize::new(0),
            fail_org: None,
        };
        let sites = discover_sites(&client, &catalog, &origin(), &[org_id]).await;
        assert!(sites.is_empty());
        assert_eq!(client.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn org_with_many_sites_pages_through_all_of_them() {
        let catalog = Catalog::embedded().expect("catalog");
        let org_id = "11111111-1111-1111-1111-111111111111".to_owned();
        let full_page: Vec<_> = (0..PAGE_LIMIT)
            .map(|i| site_json(&format!("22222222-2222-2222-2222-{i:012}")))
            .collect();
        let last_page = vec![site_json("33333333-3333-3333-3333-333333333333")];
        let client = PagedClient {
            pages: BTreeMap::from([
                ((org_id.clone(), 1), full_page),
                ((org_id.clone(), 2), last_page),
            ]),
            calls: AtomicUsize::new(0),
            fail_org: None,
        };
        let sites =
            discover_sites(&client, &catalog, &origin(), std::slice::from_ref(&org_id)).await;
        assert_eq!(sites.len(), PAGE_LIMIT as usize + 1);
        assert!(sites.values().all(|org| org == &org_id));
        assert_eq!(client.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn one_failing_org_does_not_block_the_others() {
        let catalog = Catalog::embedded().expect("catalog");
        let good_org = "11111111-1111-1111-1111-111111111111".to_owned();
        let bad_org = "44444444-4444-4444-4444-444444444444".to_owned();
        let site_id = "22222222-2222-2222-2222-222222222222";
        let client = PagedClient {
            pages: BTreeMap::from([((good_org.clone(), 1), vec![site_json(site_id)])]),
            calls: AtomicUsize::new(0),
            fail_org: Some(bad_org.clone()),
        };
        let sites =
            discover_sites(&client, &catalog, &origin(), &[bad_org, good_org.clone()]).await;
        assert_eq!(sites.get(site_id), Some(&good_org));
        assert_eq!(sites.len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_refresh_pass_picks_up_a_newly_added_site() {
        let catalog = Catalog::embedded().expect("catalog");
        let org_id = "11111111-1111-1111-1111-111111111111".to_owned();
        let existing = "22222222-2222-2222-2222-222222222222";
        let added = "33333333-3333-3333-3333-333333333333";

        let before = PagedClient {
            pages: BTreeMap::from([((org_id.clone(), 1), vec![site_json(existing)])]),
            calls: AtomicUsize::new(0),
            fail_org: None,
        };
        let first =
            discover_sites(&before, &catalog, &origin(), std::slice::from_ref(&org_id)).await;
        assert_eq!(first.len(), 1);
        assert!(first.contains_key(existing));

        let after = PagedClient {
            pages: BTreeMap::from([(
                (org_id.clone(), 1),
                vec![site_json(existing), site_json(added)],
            )]),
            calls: AtomicUsize::new(0),
            fail_org: None,
        };
        let second =
            discover_sites(&after, &catalog, &origin(), std::slice::from_ref(&org_id)).await;
        assert_eq!(second.len(), 2);
        assert!(second.contains_key(existing));
        assert!(second.contains_key(added));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refresh_loop_swaps_the_handler_site_map() {
        let org_id = "11111111-1111-1111-1111-111111111111".to_owned();
        let site_id = "22222222-2222-2222-2222-222222222222";
        let client = std::sync::Arc::new(PagedClient {
            pages: BTreeMap::from([((org_id.clone(), 1), vec![site_json(site_id)])]),
            calls: AtomicUsize::new(0),
            fail_org: None,
        });
        let handler = MistHandler::with_client(
            "https://api.mist.com/",
            vec![org_id.clone()],
            BTreeMap::new(),
            client,
        )
        .expect("handler");

        let task = spawn_refresh_loop(handler.clone(), Duration::from_millis(5));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if handler.sites_snapshot().contains_key(site_id) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "refresh loop did not populate the site map in time"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        task.abort();

        assert_eq!(handler.sites_snapshot().get(site_id), Some(&org_id));
    }
}

//! Selector resolution for the collapsed WAN edge tools.
//!
//! These tools accept a selector (scope, mode, object) and resolve it to
//! exactly one catalog operation before dispatch. Resolution is pure so it can
//! be tested without a client; the wiring is proven separately in
//! `tests/wan_tools.rs`.

/// Which scope a collapsed tool was called with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WanScope {
    /// Organization-scoped variant.
    Org,
    /// Site-scoped variant.
    Site,
}

/// Whether a stats tool returns records or a count distribution.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum StatsMode {
    /// Return matching records.
    #[default]
    Records,
    /// Return a count distribution.
    Count,
}

/// One resolved dispatch target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Resolved {
    /// Exact catalog operation ID.
    pub operation_id: &'static str,
    /// Names this operation carries in its path rather than its query.
    pub path_names: &'static [&'static str],
}

/// Exactly one of `org_id` or `site_id` is required.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ScopeError;

/// Resolve exactly-one-of `org_id`/`site_id`.
pub(crate) fn resolve_scope(
    org_id: Option<&str>,
    site_id: Option<&str>,
) -> Result<WanScope, ScopeError> {
    match (org_id, site_id) {
        (Some(_), None) => Ok(WanScope::Org),
        (None, Some(_)) => Ok(WanScope::Site),
        _ => Err(ScopeError),
    }
}

/// Resolve the gateway inventory search for a scope.
pub(crate) fn wan_edges(scope: WanScope) -> Resolved {
    match scope {
        WanScope::Org => Resolved {
            operation_id: "searchOrgDevices",
            path_names: &["org_id"],
        },
        WanScope::Site => Resolved {
            operation_id: "searchSiteDevices",
            path_names: &["site_id"],
        },
    }
}

/// Resolve gateway stats to the site-wide or per-device operation.
pub(crate) fn wan_edge_stats(per_device: bool) -> Resolved {
    if per_device {
        Resolved {
            operation_id: "getSiteInsightMetricsForGateway",
            path_names: &["site_id", "device_id"],
        }
    } else {
        Resolved {
            operation_id: "getSiteGatewayMetrics",
            path_names: &["site_id"],
        }
    }
}

/// Resolve WAN IPsec tunnel stats for a mode.
pub(crate) fn tunnels(mode: StatsMode) -> Resolved {
    match mode {
        StatsMode::Records => Resolved {
            operation_id: "searchOrgTunnelsStats",
            path_names: &["org_id"],
        },
        StatsMode::Count => Resolved {
            operation_id: "countOrgTunnelsStats",
            path_names: &["org_id"],
        },
    }
}

/// Resolve SD-WAN overlay peer path stats for a mode.
pub(crate) fn peer_paths(mode: StatsMode) -> Resolved {
    match mode {
        StatsMode::Records => Resolved {
            operation_id: "searchOrgPeerPathStats",
            path_names: &["org_id"],
        },
        StatsMode::Count => Resolved {
            operation_id: "countOrgPeerPathStats",
            path_names: &["org_id"],
        },
    }
}

/// Resolve BGP peer stats for a scope and mode.
pub(crate) fn bgp_peers(scope: WanScope, mode: StatsMode) -> Resolved {
    match (scope, mode) {
        (WanScope::Org, StatsMode::Records) => Resolved {
            operation_id: "searchOrgBgpStats",
            path_names: &["org_id"],
        },
        (WanScope::Org, StatsMode::Count) => Resolved {
            operation_id: "countOrgBgpStats",
            path_names: &["org_id"],
        },
        (WanScope::Site, StatsMode::Records) => Resolved {
            operation_id: "searchSiteBgpStats",
            path_names: &["site_id"],
        },
        (WanScope::Site, StatsMode::Count) => Resolved {
            operation_id: "countSiteBgpStats",
            path_names: &["site_id"],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_requires_exactly_one_identifier() {
        assert_eq!(resolve_scope(Some("org"), None), Ok(WanScope::Org));
        assert_eq!(resolve_scope(None, Some("site")), Ok(WanScope::Site));
        assert_eq!(resolve_scope(None, None), Err(ScopeError));
        assert_eq!(resolve_scope(Some("org"), Some("site")), Err(ScopeError));
    }

    #[test]
    fn wan_edges_resolves_per_scope() {
        assert_eq!(
            wan_edges(WanScope::Org),
            Resolved {
                operation_id: "searchOrgDevices",
                path_names: &["org_id"]
            }
        );
        assert_eq!(
            wan_edges(WanScope::Site),
            Resolved {
                operation_id: "searchSiteDevices",
                path_names: &["site_id"]
            }
        );
    }

    #[test]
    fn wan_edge_stats_selects_on_device_presence() {
        assert_eq!(
            wan_edge_stats(false),
            Resolved {
                operation_id: "getSiteGatewayMetrics",
                path_names: &["site_id"]
            }
        );
        assert_eq!(
            wan_edge_stats(true),
            Resolved {
                operation_id: "getSiteInsightMetricsForGateway",
                path_names: &["site_id", "device_id"],
            }
        );
    }

    #[test]
    fn tunnels_resolve_per_mode() {
        assert_eq!(
            tunnels(StatsMode::Records),
            Resolved {
                operation_id: "searchOrgTunnelsStats",
                path_names: &["org_id"]
            }
        );
        assert_eq!(
            tunnels(StatsMode::Count),
            Resolved {
                operation_id: "countOrgTunnelsStats",
                path_names: &["org_id"]
            }
        );
    }

    #[test]
    fn peer_paths_resolve_per_mode() {
        assert_eq!(
            peer_paths(StatsMode::Records),
            Resolved {
                operation_id: "searchOrgPeerPathStats",
                path_names: &["org_id"]
            }
        );
        assert_eq!(
            peer_paths(StatsMode::Count),
            Resolved {
                operation_id: "countOrgPeerPathStats",
                path_names: &["org_id"]
            }
        );
    }

    #[test]
    fn bgp_peers_resolve_all_four_combinations() {
        assert_eq!(
            bgp_peers(WanScope::Org, StatsMode::Records),
            Resolved {
                operation_id: "searchOrgBgpStats",
                path_names: &["org_id"]
            }
        );
        assert_eq!(
            bgp_peers(WanScope::Org, StatsMode::Count),
            Resolved {
                operation_id: "countOrgBgpStats",
                path_names: &["org_id"]
            }
        );
        assert_eq!(
            bgp_peers(WanScope::Site, StatsMode::Records),
            Resolved {
                operation_id: "searchSiteBgpStats",
                path_names: &["site_id"]
            }
        );
        assert_eq!(
            bgp_peers(WanScope::Site, StatsMode::Count),
            Resolved {
                operation_id: "countSiteBgpStats",
                path_names: &["site_id"]
            }
        );
    }
}

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

/// Resolve service path events for a mode.
pub(crate) fn service_path_events(mode: StatsMode) -> Resolved {
    match mode {
        StatsMode::Records => Resolved {
            operation_id: "searchSiteServicePathEvents",
            path_names: &["site_id"],
        },
        StatsMode::Count => Resolved {
            operation_id: "countSiteServicePathEvents",
            path_names: &["site_id"],
        },
    }
}

/// Which SLE impact view to return.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SleImpact {
    /// Gateways impacted by the metric.
    Gateways,
    /// Applications impacted by the metric.
    Applications,
    /// Aggregate impact summary.
    Summary,
}

/// Resolve an SLE impact view.
pub(crate) fn sle_impact(impact: SleImpact) -> Resolved {
    const PATHS: &[&str] = &["site_id", "scope", "scope_id", "metric"];
    let operation_id = match impact {
        SleImpact::Gateways => "listSiteSleImpactedGateways",
        SleImpact::Applications => "listSiteSleImpactedApplications",
        SleImpact::Summary => "getSiteSleImpactSummary",
    };
    Resolved {
        operation_id,
        path_names: PATHS,
    }
}

/// Where the application list comes from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AppSource {
    /// Applications observed at a site.
    Site,
    /// The constant gateway application catalog.
    Catalog,
}

/// Resolve an application listing.
///
/// The constant catalog is org- and site-independent and has no count variant,
/// so `mode` is ignored for [`AppSource::Catalog`].
pub(crate) fn applications(source: AppSource, mode: StatsMode) -> Resolved {
    match (source, mode) {
        (AppSource::Site, StatsMode::Records) => Resolved {
            operation_id: "listSiteApps",
            path_names: &["site_id"],
        },
        (AppSource::Site, StatsMode::Count) => Resolved {
            operation_id: "countSiteApps",
            path_names: &["site_id"],
        },
        (AppSource::Catalog, _) => Resolved {
            operation_id: "listGatewayApplications",
            path_names: &[],
        },
    }
}

/// A WAN edge configuration object type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WanObject {
    /// A LAN segment / network.
    Network,
    /// An application or service definition.
    Service,
    /// A service (SD-WAN steering) policy.
    ServicePolicy,
    /// A gateway template.
    GatewayTemplate,
    /// A device profile.
    DeviceProfile,
}

/// Resolve a configuration listing.
///
/// Device profiles have no site-derived listing, so a site scope is refused
/// rather than silently answered with the org listing.
pub(crate) fn list_config(object: WanObject, scope: WanScope) -> Result<Resolved, ScopeError> {
    let resolved = match (object, scope) {
        (WanObject::Network, WanScope::Org) => Resolved {
            operation_id: "listOrgNetworks",
            path_names: &["org_id"],
        },
        (WanObject::Service, WanScope::Org) => Resolved {
            operation_id: "listOrgServices",
            path_names: &["org_id"],
        },
        (WanObject::ServicePolicy, WanScope::Org) => Resolved {
            operation_id: "listOrgServicePolicies",
            path_names: &["org_id"],
        },
        (WanObject::GatewayTemplate, WanScope::Org) => Resolved {
            operation_id: "listOrgGatewayTemplates",
            path_names: &["org_id"],
        },
        (WanObject::DeviceProfile, WanScope::Org) => Resolved {
            operation_id: "listOrgDeviceProfiles",
            path_names: &["org_id"],
        },
        (WanObject::Network, WanScope::Site) => Resolved {
            operation_id: "listSiteNetworksDerived",
            path_names: &["site_id"],
        },
        (WanObject::Service, WanScope::Site) => Resolved {
            operation_id: "listSiteServicesDerived",
            path_names: &["site_id"],
        },
        (WanObject::ServicePolicy, WanScope::Site) => Resolved {
            operation_id: "listSiteServicePoliciesDerived",
            path_names: &["site_id"],
        },
        (WanObject::GatewayTemplate, WanScope::Site) => Resolved {
            operation_id: "listSiteGatewayTemplatesDerived",
            path_names: &["site_id"],
        },
        (WanObject::DeviceProfile, WanScope::Site) => return Err(ScopeError),
    };
    Ok(resolved)
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

    #[test]
    fn service_path_events_resolve_per_mode() {
        assert_eq!(
            service_path_events(StatsMode::Records),
            Resolved {
                operation_id: "searchSiteServicePathEvents",
                path_names: &["site_id"]
            }
        );
        assert_eq!(
            service_path_events(StatsMode::Count),
            Resolved {
                operation_id: "countSiteServicePathEvents",
                path_names: &["site_id"]
            }
        );
    }

    #[test]
    fn sle_impact_resolves_per_selector() {
        const PATHS: &[&str] = &["site_id", "scope", "scope_id", "metric"];
        assert_eq!(
            sle_impact(SleImpact::Gateways),
            Resolved {
                operation_id: "listSiteSleImpactedGateways",
                path_names: PATHS
            }
        );
        assert_eq!(
            sle_impact(SleImpact::Applications),
            Resolved {
                operation_id: "listSiteSleImpactedApplications",
                path_names: PATHS
            }
        );
        assert_eq!(
            sle_impact(SleImpact::Summary),
            Resolved {
                operation_id: "getSiteSleImpactSummary",
                path_names: PATHS
            }
        );
    }

    #[test]
    fn applications_resolve_source_and_mode() {
        assert_eq!(
            applications(AppSource::Site, StatsMode::Records),
            Resolved {
                operation_id: "listSiteApps",
                path_names: &["site_id"]
            }
        );
        assert_eq!(
            applications(AppSource::Site, StatsMode::Count),
            Resolved {
                operation_id: "countSiteApps",
                path_names: &["site_id"]
            }
        );
        // The constant catalog has no scope and no count variant; mode is ignored.
        assert_eq!(
            applications(AppSource::Catalog, StatsMode::Count),
            Resolved {
                operation_id: "listGatewayApplications",
                path_names: &[]
            }
        );
    }

    #[test]
    fn list_config_resolves_object_and_scope() {
        assert_eq!(
            list_config(WanObject::Network, WanScope::Org),
            Ok(Resolved {
                operation_id: "listOrgNetworks",
                path_names: &["org_id"]
            })
        );
        assert_eq!(
            list_config(WanObject::Network, WanScope::Site),
            Ok(Resolved {
                operation_id: "listSiteNetworksDerived",
                path_names: &["site_id"]
            })
        );
        assert_eq!(
            list_config(WanObject::GatewayTemplate, WanScope::Site),
            Ok(Resolved {
                operation_id: "listSiteGatewayTemplatesDerived",
                path_names: &["site_id"],
            })
        );
        // Device profiles have no site-derived listing.
        assert_eq!(
            list_config(WanObject::DeviceProfile, WanScope::Site),
            Err(ScopeError)
        );
    }
}

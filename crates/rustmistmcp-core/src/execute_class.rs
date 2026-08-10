//! How each `execute` operation is controlled.
//!
//! `create`, `update` and `delete` all have observable prior state, so a
//! change set means something for them: plan against what was read, refuse if
//! it moved between approval and apply.
//!
//! `execute` does not work that way. "Reboot this AP" is an event, not a diff,
//! and there is no `before` to bind a digest to. Forcing all 168 through the
//! same machinery would put a digest in the audit record that constrained
//! nothing — which is worse than no digest, because it reads as protection.
//!
//! So the class is split three ways rather than gated wholesale. The split was
//! made by reading all 168 operations, and [`classified_execute_operations_are_exhaustive`]
//! stops the catalog gaining an unclassified one later.
//!
//! [`classified_execute_operations_are_exhaustive`]: #tests

/// How an `execute` operation may be reached.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecuteClass {
    /// Not exposed as a tool at all.
    ///
    /// Mist portal identity flows — login, logout, 2FA, password recovery,
    /// registration, admin invitations — are not network operations, and
    /// exposing them would hand an MCP client an identity-manipulation surface
    /// with no networking value.
    ///
    /// Also covers two credential-bearing operations the upstream catalog
    /// classifies as `execute` when they are really privileged reads. An
    /// approval gate is the wrong control for those: the risk is disclosure,
    /// and a change set does not reduce disclosure at all.
    Excluded,
    /// Reachable when the grant names the operation and the subject. No change set.
    ///
    /// Reads and probes: `show*` commands, ping, traceroute, cable test,
    /// synthetic tests, LED locate. No configuration change and no service
    /// interruption.
    Diagnostic,
    /// Requires approval before it runs.
    ///
    /// Upgrades, reboots, reprovisions, client disconnects, state clears, bulk
    /// imports, licensing changes, RF automation — anything that changes device
    /// or service state.
    ///
    /// Packet capture and support-file upload are here on a *different*
    /// rationale from the rest: they neither disrupt nor reconfigure, but they
    /// move data outward. Gated as egress, not as disruption.
    Gated,
}

/// Operations never exposed as tools. See [`ExecuteClass::Excluded`].
pub const EXCLUDED_EXECUTE_OPERATIONS: &[&str] = &[
    "exportOrgSsrIdTokens",
    "generateSecretFor2faVerification",
    "getSiteDeviceZtpPassword",
    "loginOauth2",
    "logout",
    "recoverPassword",
    "sendSdkInviteEmail",
    "sendSdkInviteSms",
    "twoFactor",
    "verifyAdminInvite",
    "verifyRecoverPassword",
    "verifyRegistration",
    "verifyTwoFactor",
];

/// Operations reachable by scope alone. See [`ExecuteClass::Diagnostic`].
pub const DIAGNOSTIC_EXECUTE_OPERATIONS: &[&str] = &[
    "arpFromDevice",
    "cableTestFromSwitch",
    "initiateSiteAnalyzeSpectrum",
    "lookup",
    "monitorSiteDeviceTraffic",
    "pingFromDevice",
    "pingOrgWebhook",
    "pingSiteWebhook",
    "pollSiteSwitchStats",
    "runSiteSrxTopCommand",
    "servicePingFromSsr",
    "showSiteDeviceArpTable",
    "showSiteDeviceBgpSummary",
    "showSiteDeviceDhcpLeases",
    "showSiteDeviceDot1xTable",
    "showSiteDeviceEvpnDatabase",
    "showSiteDeviceForwardingTable",
    "showSiteDeviceMacTable",
    "showSiteGatewayOspfDatabase",
    "showSiteGatewayOspfInterfaces",
    "showSiteGatewayOspfNeighbors",
    "showSiteGatewayOspfSummary",
    "showSiteSsrAndSrxRoutes",
    "showSiteSsrAndSrxSessions",
    "showSiteSsrServicePath",
    "startInstallerLocateDevice",
    "startSiteLocateDevice",
    "startSiteSwitchRadiusSyntheticTest",
    "stopInstallerLocateDevice",
    "stopSiteLocateDevice",
    "testOrgCradlepointConnection",
    "testSiteSsrDnsResolution",
    "testSiteWlanSmsGlobal",
    "testSiteWlanTelstraSetup",
    "testSiteWlanTwilioSetup",
    "tracerouteFromDevice",
    "triggerSiteDeviceSyntheticTest",
    "triggerSiteSyntheticTest",
    "validateOrgIdpCredential",
    "verifyOrgCustomBucket",
];

/// Operations requiring approval. See [`ExecuteClass::Gated`].
pub const GATED_EXECUTE_OPERATIONS: &[&str] = &[
    "UploadOrgTicketAttachment",
    "addInstallerDeviceImage",
    "addOrgInventory",
    "addOrgMxEdgeImage",
    "addOrgTicketComment",
    "addSiteDeviceImage",
    "addSiteMapImage",
    "bounceDevicePort",
    "bounceOrgMxEdgeDataPorts",
    "cancelOrgDeviceUpgrade",
    "cancelOrgMxEdgeUpgrade",
    "cancelOrgSsrUpgrade",
    "cancelSiteDeviceUpgrade",
    "cancelSiteMxEdgeUpgrade",
    "claimInstallerDevices",
    "claimMspLicense",
    "claimOrgLicense",
    "claimOrgMxEdge",
    "clearAllLearnedMacsFromPortOnSwitch",
    "clearBpduErrorsFromPortsOnSwitch",
    "clearOrgCertificates",
    "clearSiteApAutoOrient",
    "clearSiteApAutoplacement",
    "clearSiteAutoMapAssignment",
    "clearSiteDeviceDot1xSession",
    "clearSiteDeviceMacTable",
    "clearSiteDevicePendingVersion",
    "clearSiteDevicePolicyHitCount",
    "clearSiteDeviceSession",
    "clearSiteMultipleDevicePendingVersion",
    "clearSiteSsrArpCache",
    "clearSiteSsrBgpRoutes",
    "controlOrgMxEdgeServices",
    "createOrUpdateInstallerSites",
    "deauthSiteWirelessClientsConnectedToARogue",
    "disconnectOrgMxEdgeTuntermAps",
    "disconnectSiteMultipleClients",
    "disconnectSiteWirelessClient",
    "enableOrgE911Report",
    "enableSiteDeviceZigbeeJoin",
    "importInstallerMap",
    "importOrgAssets",
    "importOrgMapToSite",
    "importOrgMaps",
    "importOrgNacCrl",
    "importOrgPsks",
    "importOrgUserMacs",
    "importSiteAssets",
    "importSiteDevices",
    "importSiteMaps",
    "importSitePsks",
    "importSiteWayfindings",
    "kickSiteDeviceZigbeeClients",
    "login",
    "manageMspOrgs",
    "moveOrDeleteMspLicenseToAnotherOrg",
    "moveOrDeleteOrgLicenseToAnotherOrg",
    "optimizeInstallerRrm",
    "optimizeSiteRrm",
    "preemptSitesMxTunnel",
    "readoptSiteOctermDevice",
    "reauthOrgDot1xWiredClient",
    "reauthOrgDot1xWirelessClient",
    "reauthSiteDot1xWiredClient",
    "reauthSiteDot1xWirelessClient",
    "rebootOrgOtherDevice",
    "reevaluateOrgAutoAssignment",
    "rejoinSiteIotEndpointZigbee",
    "releaseSiteDeviceDhcpLease",
    "releaseSiteSsrDhcpLease",
    "reprovisionSiteAllDevices",
    "reprovisionSiteOctermDevice",
    "resetSiteAllApsToUseRrm",
    "resetSiteMlStatsByMap",
    "restartOrgMxEdge",
    "restartSiteDevice",
    "restartSiteMultipleDevices",
    "restoreSiteDeviceBackupVersion",
    "restoreSiteMultipleDeviceBackupVersion",
    "runSiteApAutoplacement",
    "sendOrgNacClientCoA",
    "sendSiteDevicesArbitraryBleBeacon",
    "sendSiteNacClientCoA",
    "startOrgPacketCapture",
    "startSiteApAutoOrientation",
    "startSiteAutoMapAssignment",
    "startSiteDeviceZigbeeEventTrail",
    "startSiteDeviceZigbeePacketTrail",
    "startSiteMapAutoGeofence",
    "startSiteMapAutoZone",
    "startSiteMapsAutoGeofence",
    "startSitePacketCapture",
    "startSiteRecording",
    "stopSiteRfdiagRecording",
    "syncOrgCradlepointRouters",
    "toogleSiteDeviceVcRoutingEnginesRole",
    "upgradeDevice",
    "upgradeDeviceBios",
    "upgradeDeviceFPGA",
    "upgradeOrgDevices",
    "upgradeOrgJsiDevice",
    "upgradeOrgMxEdges",
    "upgradeOrgSsrs",
    "upgradeSiteDevices",
    "upgradeSiteDevicesBios",
    "upgradeSiteDevicesFpga",
    "upgradeSiteMxEdges",
    "upgradeSsr",
    "uploadOrgMxEdgeSupportFiles",
    "uploadOrgNacPortalImage",
    "uploadOrgPskPortalImage",
    "uploadOrgWlanPortalImage",
    "uploadSiteDeviceSupportFile",
    "uploadSiteMxEdgeSupportFiles",
    "uploadSiteWlanPortalImage",
];

/// Classify one `execute` operation.
///
/// An operation absent from all three lists is treated as [`ExecuteClass::Gated`],
/// so a catalog regeneration that adds an operation cannot make it *more*
/// reachable by accident. That default is a backstop, not a design: the
/// exhaustiveness test asserts it never fires.
#[must_use]
pub fn execute_class(operation_id: &str) -> ExecuteClass {
    if EXCLUDED_EXECUTE_OPERATIONS.contains(&operation_id) {
        ExecuteClass::Excluded
    } else if DIAGNOSTIC_EXECUTE_OPERATIONS.contains(&operation_id) {
        ExecuteClass::Diagnostic
    } else {
        ExecuteClass::Gated
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{Catalog, MistAction};
    use std::collections::BTreeSet;

    fn catalog_execute_operations() -> BTreeSet<String> {
        Catalog::embedded()
            .expect("embedded catalog")
            .operations
            .iter()
            .filter(|operation| operation.action == MistAction::Execute)
            .map(|operation| operation.operation_id.clone())
            .collect()
    }

    fn classified() -> BTreeSet<String> {
        EXCLUDED_EXECUTE_OPERATIONS
            .iter()
            .chain(DIAGNOSTIC_EXECUTE_OPERATIONS)
            .chain(GATED_EXECUTE_OPERATIONS)
            .map(|id| (*id).to_owned())
            .collect()
    }

    /// Every `execute` operation in the catalog has been classified by hand.
    ///
    /// This is the test that stops the classification decaying. Regenerating
    /// the catalog against a newer Mist spec can introduce operations, and
    /// without this they would land silently on the `Gated` default — which is
    /// safe, but means nobody ever read them. A new operation should force a
    /// decision, not inherit one.
    #[test]
    fn classified_execute_operations_are_exhaustive() {
        let catalog = catalog_execute_operations();
        let classified = classified();
        let unclassified: Vec<_> = catalog.difference(&classified).collect();
        assert!(
            unclassified.is_empty(),
            "these execute operations are new since the classification pass and \
             need a decision — excluded, diagnostic, or gated: {unclassified:?}"
        );
    }

    /// No classified name is absent from the catalog.
    ///
    /// Catches a typo in the lists, and catches an operation Mist has removed —
    /// either way the entry is dead and should not sit there implying coverage.
    #[test]
    fn no_classified_operation_is_missing_from_the_catalog() {
        let catalog = catalog_execute_operations();
        let classified = classified();
        let stale: Vec<_> = classified.difference(&catalog).collect();
        assert!(
            stale.is_empty(),
            "these classified operations are not in the catalog — typo, or removed upstream: {stale:?}"
        );
    }

    /// The three lists do not overlap.
    #[test]
    fn an_operation_belongs_to_exactly_one_class() {
        let mut seen = BTreeSet::new();
        let mut duplicated = Vec::new();
        for id in EXCLUDED_EXECUTE_OPERATIONS
            .iter()
            .chain(DIAGNOSTIC_EXECUTE_OPERATIONS)
            .chain(GATED_EXECUTE_OPERATIONS)
        {
            if !seen.insert(*id) {
                duplicated.push(*id);
            }
        }
        assert!(
            duplicated.is_empty(),
            "an operation appears in more than one class, so its control depends \
             on list order rather than on a decision: {duplicated:?}"
        );
    }

    /// The identity flows and credential reads stay out of the tool surface.
    ///
    /// Named individually rather than by count: a future edit that quietly
    /// moves one of these into a reachable class is exactly what this guards.
    #[test]
    fn identity_and_credential_operations_are_excluded() {
        for operation in [
            "loginOauth2",
            "logout",
            "twoFactor",
            "verifyTwoFactor",
            "recoverPassword",
            "verifyRegistration",
            "verifyAdminInvite",
            "exportOrgSsrIdTokens",
            "getSiteDeviceZtpPassword",
        ] {
            assert_eq!(
                execute_class(operation),
                ExecuteClass::Excluded,
                "{operation} must not be reachable as a tool"
            );
        }
    }

    /// Fleet-wide disruption is gated, and diagnostics are not.
    #[test]
    fn disruption_is_gated_and_probes_are_not() {
        assert_eq!(execute_class("upgradeOrgDevices"), ExecuteClass::Gated);
        assert_eq!(
            execute_class("restartSiteMultipleDevices"),
            ExecuteClass::Gated
        );
        assert_eq!(
            execute_class("toogleSiteDeviceVcRoutingEnginesRole"),
            ExecuteClass::Gated,
            "a virtual-chassis RE switchover is not a diagnostic"
        );
        assert_eq!(
            execute_class("startSitePacketCapture"),
            ExecuteClass::Gated,
            "packet capture is gated as data egress, not as disruption"
        );
        assert_eq!(execute_class("pingFromDevice"), ExecuteClass::Diagnostic);
        assert_eq!(
            execute_class("showSiteDeviceMacTable"),
            ExecuteClass::Diagnostic
        );
    }

    /// An unknown operation fails closed.
    #[test]
    fn an_unknown_operation_defaults_to_gated() {
        assert_eq!(
            execute_class("someOperationMistAddedYesterday"),
            ExecuteClass::Gated,
            "the default must be the restrictive class, not the reachable one"
        );
    }
}

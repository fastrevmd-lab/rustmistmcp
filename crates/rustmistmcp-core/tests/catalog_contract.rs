//! Contract tests for the generated, audited Mist operation catalog.

use rustmistmcp_core::catalog::{
    Catalog, MistAction, MistCapability, PaginationMode, VerificationPolicy,
};

const CATALOG_JSON: &str = include_str!("../../../docs/mist-api/catalog.json");
const FROZEN_INVENTORY_JSON: &str =
    include_str!("../../../docs/mist-api/frozen-reference-inventory.json");
const PARITY_JSON: &str = include_str!("../../../docs/mist-api/parity.json");

#[test]
fn audited_catalog_covers_each_current_operation_safely_and_deterministically() {
    let catalog = Catalog::from_json(CATALOG_JSON).expect("catalog is valid");

    assert_eq!(
        catalog.source.sha256,
        "2c3d769ef188bbce1b9db7a0774b5a10812d0a5bc11960b768de47b66bb88bbf"
    );
    assert_eq!(catalog.source.api_version, "2607.1.0");
    assert_eq!(catalog.operations.len(), 1_059);
    assert_eq!(
        catalog
            .operation("getOrgAoscxRegisterCmd")
            .expect("AOSCX operation is catalogued")
            .tool,
        "mist_get_org_aoscx_register_cmd"
    );

    let mut operation_ids = std::collections::BTreeSet::new();
    let mut operation_keys = std::collections::BTreeSet::new();
    let mut tools = std::collections::BTreeSet::new();
    for operation in &catalog.operations {
        assert!(operation_ids.insert(&operation.operation_id));
        assert!(operation_keys.insert(&operation.operation_key));
        assert!(tools.insert(&operation.tool));
        assert!(operation.path.starts_with("/api/v1/"));
        assert!(!operation.path.contains(".."));
        assert!(!operation.path.contains('?'));
        assert!(!operation.path.contains('#'));
        assert!(!operation.scope.is_empty());
        assert!(!operation.target_selectors.is_empty());
        assert!(matches!(
            operation.capability,
            MistCapability::OrdinaryRead
                | MistCapability::PrivilegedRead
                | MistCapability::Create
                | MistCapability::Update
                | MistCapability::Delete
                | MistCapability::Execute
        ));
        assert!(matches!(
            operation.action,
            MistAction::OrdinaryRead
                | MistAction::PrivilegedRead
                | MistAction::Create
                | MistAction::Update
                | MistAction::Delete
                | MistAction::Execute
        ));
        assert!(matches!(
            operation.pagination,
            PaginationMode::None | PaginationMode::PageLimit | PaginationMode::SearchAfter
        ));
        assert!(matches!(
            operation.verification,
            VerificationPolicy::None
                | VerificationPolicy::ApiAcknowledged
                | VerificationPolicy::FollowUpRead
        ));
        for media_type in &operation.request_media_types {
            assert!(matches!(
                media_type.as_str(),
                "application/json" | "multipart/form-data"
            ));
        }
    }
}

#[test]
fn parity_manifest_and_catalog_freeze_reference_delta_and_request_media_truth() {
    let parity: serde_json::Value = serde_json::from_str(PARITY_JSON).expect("parity is JSON");
    let catalog = Catalog::from_json(CATALOG_JSON).expect("catalog is valid");
    assert_eq!(parity["manifest_version"], 1);
    assert_eq!(
        parity["operations"]
            .as_array()
            .expect("parity operations are an array")
            .len(),
        1_049
    );
    let exceptions = parity["exceptions"]
        .as_array()
        .expect("parity exceptions are an array");
    assert_eq!(
        exceptions.len(),
        34,
        "10 missing + 1 stale + 23 frozen transport gaps"
    );
    for operation_key in [
        "GET /api/v1/sites/{site_id}/iotendpoints/count",
        "GET /api/v1/orgs/{org_id}/aoscx/register_cmd",
        "GET /api/v1/orgs/{org_id}/edgeconnect/register_cmd",
        "POST /api/v1/sites/{site_id}/devices/{device_id}/zigbee_kick",
        "GET /api/v1/const/marvisclient_events",
        "POST /api/v1/sites/{site_id}/iotendpoints/{id}/zigbee_rejoin",
        "GET /api/v1/sites/{site_id}/devices/{device_id}/flow_records/search",
        "POST /api/v1/sites/{site_id}/devices/{device_id}/zigbee_event_trail",
        "POST /api/v1/sites/{site_id}/devices/{device_id}/zigbee_packet_trail",
        "DELETE /api/v1/sites/{site_id}/devices/{device_id}/zigbee_join",
        "GET /api/v1/orgs/{org_id}/aos/register_cmd",
    ] {
        assert!(exceptions.iter().any(|exception| {
            exception["operation_key"] == operation_key
                && exception["status"] == "unsupported"
                && exception["issue"] == "docs/mist-api/frozen-reference-inventory.json"
                && exception["expires_on"] == "2026-08-28"
        }));
    }
    assert!(exceptions.iter().any(|exception| {
        exception["operation_key"] == "POST /api/v1/orgs/{org_id}/usermacs/import"
            && exception["status"] == "transport_blocked"
    }));
    assert_eq!(
        exceptions
            .iter()
            .filter(|exception| exception["status"] == "transport_blocked")
            .count(),
        23
    );
    assert_eq!(catalog.audit.operation_wrappers, 1_050);
    assert_eq!(catalog.audit.meta_tools, 3);
    assert_eq!(catalog.audit.missing_current_operations, 10);
    assert_eq!(catalog.audit.stale_unmatched_wrappers, 1);
    assert_eq!(
        catalog.audit.stale_wrapper_tool,
        "mist_get_org_aos_register_cmd"
    );
    assert_eq!(catalog.audit.media_accounting.json_only_operations, 333);
    assert_eq!(catalog.audit.media_accounting.multipart_only_operations, 16);
    assert_eq!(catalog.audit.media_accounting.mixed_media_operations, 7);
    assert_eq!(catalog.audit.media_accounting.json_media_entries, 340);
    assert_eq!(catalog.audit.media_accounting.multipart_media_entries, 23);
}

#[test]
fn parity_capabilities_exactly_match_frozen_wrapper_capabilities() {
    let parity: serde_json::Value = serde_json::from_str(PARITY_JSON).expect("parity is JSON");
    let inventory: serde_json::Value =
        serde_json::from_str(FROZEN_INVENTORY_JSON).expect("inventory is JSON");
    let parity_by_tool: std::collections::BTreeMap<_, _> = parity["operations"]
        .as_array()
        .expect("parity operations are an array")
        .iter()
        .map(|operation| {
            (
                operation["tool"].as_str().expect("tool is string"),
                operation,
            )
        })
        .collect();
    let mut distribution = std::collections::BTreeMap::new();
    for wrapper in inventory["registered_surface"]["tools"]
        .as_array()
        .expect("frozen wrappers are an array")
    {
        let Some(operation_id) = wrapper["operation_id"].as_str() else {
            continue;
        };
        let expected = match wrapper["capability"]
            .as_str()
            .expect("capability is string")
        {
            "READ" => "read",
            "WRITE" => "write",
            "WRITE_DELETE" => "write_delete",
            other => panic!("unknown frozen wrapper capability: {other}"),
        };
        let operation = parity_by_tool
            .get(wrapper["tool"].as_str().expect("tool is string"))
            .expect("mapped frozen wrapper is in parity");
        assert_eq!(operation["operation_id"], operation_id);
        assert_eq!(operation["capability"], expected);
        *distribution.entry(expected).or_insert(0usize) += 1;
    }
    assert_eq!(
        distribution,
        std::collections::BTreeMap::from([("read", 524), ("write", 408), ("write_delete", 117)])
    );
}

#[test]
fn catalog_preserves_resolvable_response_and_request_schema_contracts() {
    let catalog: serde_json::Value = serde_json::from_str(CATALOG_JSON).expect("catalog is JSON");
    let operation = |operation_id: &str| {
        catalog["operations"]
            .as_array()
            .expect("operations are an array")
            .iter()
            .find(|operation| operation["operation_id"] == operation_id)
            .expect("operation is catalogued")
    };

    let alarms = operation("listAlarmDefinitions");
    assert_eq!(
        alarms["responses"]["200"]["application/json"]["$ref"],
        "#/components/schemas/const_alarm_definitions"
    );
    let calls = operation("countSiteCalls");
    let rating = calls["parameters"]
        .as_array()
        .expect("parameters are an array")
        .iter()
        .find(|parameter| parameter["name"] == "rating")
        .expect("rating is retained");
    assert_eq!(rating["schema"]["minimum"], 1);
    assert_eq!(rating["schema"]["maximum"], 5);
    assert_eq!(
        catalog["components"]["parameters"]["client_mac"]["schema"]["pattern"],
        "^[0-9a-fA-F]{12}$"
    );
    let user_macs = operation("importOrgUserMacs");
    assert_eq!(
        user_macs["request_schemas"]["multipart/form-data"]["properties"]["file"]["format"],
        "binary"
    );
    assert_eq!(
        catalog["components"]["schemas"]["const_alarm_definitions"]["type"],
        "array"
    );
}

#[test]
fn catalog_uses_exact_reviewed_security_actions_and_verification_policies() {
    let catalog: serde_json::Value = serde_json::from_str(CATALOG_JSON).expect("catalog is JSON");
    let operation = |operation_id: &str| {
        catalog["operations"]
            .as_array()
            .expect("operations are an array")
            .iter()
            .find(|operation| operation["operation_id"] == operation_id)
            .expect("operation is catalogued")
    };
    for (operation_id, action) in [
        ("updateOrgUiSetting", "update"),
        ("updateSelfEmail", "update"),
        ("deleteOrgPskList", "delete"),
        ("revokeOrgIssuedClientCertificates", "delete"),
        ("listOrgApiTokens", "privileged_read"),
        ("getApiToken", "privileged_read"),
    ] {
        assert_eq!(operation(operation_id)["action"], action, "{operation_id}");
    }
    assert_ne!(
        operation("updateOrgUiSetting")["verification"],
        "api_acknowledged"
    );
    assert_eq!(
        operation("updateOrgUiSetting")["follow_up_operation_id"],
        "getOrgUiSetting"
    );
    assert_eq!(
        operation("updateOrgUiSetting")["verification_predicate"],
        "request_projection_equals_response"
    );
    assert_eq!(
        catalog["operations"]
            .as_array()
            .expect("operations are an array")
            .iter()
            .filter(|operation| operation["verification"] == "follow_up_read")
            .count(),
        74
    );
}

#[test]
fn catalog_loader_rejects_cross_field_tampering() {
    let source: serde_json::Value = serde_json::from_str(CATALOG_JSON).expect("catalog is JSON");
    for (field, value) in [
        ("operation_key", serde_json::json!("POST /wrong")),
        ("tool", serde_json::json!("mist_unrelated")),
        ("scope", serde_json::json!("wrong")),
        ("action", serde_json::json!("execute")),
        ("source_fingerprint", serde_json::json!("0".repeat(64))),
    ] {
        let mut tampered = source.clone();
        tampered["operations"][0][field] = value;
        assert!(
            Catalog::from_json(&serde_json::to_string(&tampered).expect("JSON writes")).is_err(),
            "loader accepted tampered {field}"
        );
    }
    let mut unsorted = source;
    unsorted["operations"]
        .as_array_mut()
        .expect("operations are array")
        .swap(0, 1);
    assert!(Catalog::from_json(&serde_json::to_string(&unsorted).expect("JSON writes")).is_err());
}

#[test]
fn operation_name_transform_handles_acronyms_and_digits() {
    assert_eq!(
        Catalog::tool_name("getOrgAOSCXRegisterCmd").expect("safe ID"),
        "mist_get_org_aoscx_register_cmd"
    );
    assert_eq!(
        Catalog::tool_name("getOAuth2WiFiIoTStatus").expect("safe ID"),
        "mist_get_oauth2_wifi_iot_status"
    );
}

#[test]
fn tool_name_rejects_non_ascii_or_non_identifier_operation_ids() {
    for operation_id in ["", "1bad", "bad_name", "bad-id", "éclair"] {
        assert!(Catalog::tool_name(operation_id).is_err(), "{operation_id}");
    }
}

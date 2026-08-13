//! Write targets for WAN edge configuration objects.
//!
//! Each write operation is paired with the read that produces the `before`
//! state its digest binds to. That pairing is the reason this module exists:
//! a change set whose `before` came from the wrong read binds its digest to
//! the wrong object's state, which is worse than no digest because the audit
//! record still says the change was digest-bound.

use crate::server::wan::WanObject;

/// Which write a change set performs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WriteVerb {
    /// Create a new object. Has no prior state.
    Create,
    /// Update an existing object.
    Update,
}

/// One write operation and the read that produces its `before` state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WriteTarget {
    /// Catalog operation ID for the write.
    pub write_operation_id: &'static str,
    /// Catalog operation ID for the read that produces `before`.
    ///
    /// For a create this is the read that would fetch the object once it
    /// exists; it is not called at plan time, because a create has no prior
    /// state.
    pub read_operation_id: &'static str,
    /// Path parameter name carrying the object's own identifier.
    pub id_path_name: &'static str,
    /// Whether this object's operations are `privileged_read`/privileged write.
    pub privileged: bool,
}

/// Resolve the write target for an object and verb.
pub(crate) fn write_target(object: WanObject, verb: WriteVerb) -> WriteTarget {
    match (object, verb) {
        (WanObject::Network, WriteVerb::Create) => WriteTarget {
            write_operation_id: "createOrgNetwork",
            read_operation_id: "getOrgNetwork",
            id_path_name: "network_id",
            privileged: false,
        },
        (WanObject::Network, WriteVerb::Update) => WriteTarget {
            write_operation_id: "updateOrgNetwork",
            read_operation_id: "getOrgNetwork",
            id_path_name: "network_id",
            privileged: false,
        },
        (WanObject::Service, WriteVerb::Create) => WriteTarget {
            write_operation_id: "createOrgService",
            read_operation_id: "getOrgService",
            id_path_name: "service_id",
            privileged: false,
        },
        (WanObject::Service, WriteVerb::Update) => WriteTarget {
            write_operation_id: "updateOrgService",
            read_operation_id: "getOrgService",
            id_path_name: "service_id",
            privileged: false,
        },
        (WanObject::ServicePolicy, WriteVerb::Create) => WriteTarget {
            write_operation_id: "createOrgServicePolicy",
            read_operation_id: "getOrgServicePolicy",
            id_path_name: "servicepolicy_id",
            privileged: false,
        },
        (WanObject::ServicePolicy, WriteVerb::Update) => WriteTarget {
            write_operation_id: "updateOrgServicePolicy",
            read_operation_id: "getOrgServicePolicy",
            id_path_name: "servicepolicy_id",
            privileged: false,
        },
        (WanObject::GatewayTemplate, WriteVerb::Create) => WriteTarget {
            write_operation_id: "createOrgGatewayTemplate",
            read_operation_id: "getOrgGatewayTemplate",
            id_path_name: "gatewaytemplate_id",
            privileged: true,
        },
        (WanObject::GatewayTemplate, WriteVerb::Update) => WriteTarget {
            write_operation_id: "updateOrgGatewayTemplate",
            read_operation_id: "getOrgGatewayTemplate",
            id_path_name: "gatewaytemplate_id",
            privileged: true,
        },
        (WanObject::DeviceProfile, WriteVerb::Create) => WriteTarget {
            write_operation_id: "createOrgDeviceProfile",
            read_operation_id: "getOrgDeviceProfile",
            id_path_name: "deviceprofile_id",
            privileged: true,
        },
        (WanObject::DeviceProfile, WriteVerb::Update) => WriteTarget {
            write_operation_id: "updateOrgDeviceProfile",
            read_operation_id: "getOrgDeviceProfile",
            id_path_name: "deviceprofile_id",
            privileged: true,
        },
    }
}

/// Why a patch was refused before a change set was created.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PatchError {
    /// The patch tried to set `mist_configured`.
    MistConfigured,
}

/// Refuse any patch that touches `mist_configured`, at any depth.
///
/// That field decides whether Mist owns a device's configuration, so changing
/// it decides who may configure the device at all — a different kind of act
/// from changing what a configuration says, and one with fleet-wide reach. It
/// spans two capabilities (`update` and `create`), so no capability-based gate
/// can contain it; refusing the field is the only control that holds. The
/// refusal happens before a change set exists so approval cannot override it.
pub(crate) fn reject_config_authority(patch: &serde_json::Value) -> Result<(), PatchError> {
    match patch {
        serde_json::Value::Object(map) => {
            if map.contains_key("mist_configured") {
                return Err(PatchError::MistConfigured);
            }
            for value in map.values() {
                reject_config_authority(value)?;
            }
            Ok(())
        }
        serde_json::Value::Array(values) => {
            for value in values {
                reject_config_authority(value)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Apply a JSON merge-patch to the object read from Mist.
///
/// All five objects update via `PUT`, which replaces the whole object, so a
/// caller sending only the field it wants changed would silently drop every
/// other field. Merging onto the `before` state removes that hazard. Two
/// behaviours must be documented wherever this is exposed: **arrays replace
/// wholesale** (there is no element-wise edit), and **`null` deletes a field**
/// rather than setting it to null.
pub(crate) fn merge_patch(
    before: &serde_json::Value,
    patch: &serde_json::Value,
) -> serde_json::Value {
    let serde_json::Value::Object(patch_map) = patch else {
        return patch.clone();
    };
    let mut merged = match before {
        serde_json::Value::Object(before_map) => before_map.clone(),
        _ => serde_json::Map::new(),
    };
    for (key, value) in patch_map {
        if value.is_null() {
            merged.remove(key);
        } else if let Some(existing) = merged.get(key) {
            merged.insert(key.clone(), merge_patch(existing, value));
        } else {
            merged.insert(key.clone(), value.clone());
        }
    }
    serde_json::Value::Object(merged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn update_targets_pair_each_write_with_its_own_read() {
        let network = write_target(WanObject::Network, WriteVerb::Update);
        assert_eq!(network.write_operation_id, "updateOrgNetwork");
        assert_eq!(network.read_operation_id, "getOrgNetwork");
        assert_eq!(network.id_path_name, "network_id");
        assert!(!network.privileged);

        let template = write_target(WanObject::GatewayTemplate, WriteVerb::Update);
        assert_eq!(template.write_operation_id, "updateOrgGatewayTemplate");
        assert_eq!(template.read_operation_id, "getOrgGatewayTemplate");
        assert_eq!(template.id_path_name, "gatewaytemplate_id");
        assert!(template.privileged);
    }

    #[test]
    fn create_targets_use_the_collection_endpoint() {
        let service = write_target(WanObject::Service, WriteVerb::Create);
        assert_eq!(service.write_operation_id, "createOrgService");
        assert_eq!(service.read_operation_id, "getOrgService");

        let profile = write_target(WanObject::DeviceProfile, WriteVerb::Create);
        assert_eq!(profile.write_operation_id, "createOrgDeviceProfile");
        assert!(profile.privileged);
    }

    #[test]
    fn every_object_and_verb_resolves() {
        for object in [
            WanObject::Network,
            WanObject::Service,
            WanObject::ServicePolicy,
            WanObject::GatewayTemplate,
            WanObject::DeviceProfile,
        ] {
            for verb in [WriteVerb::Create, WriteVerb::Update] {
                let target = write_target(object, verb);
                assert!(target.write_operation_id.starts_with(match verb {
                    WriteVerb::Create => "create",
                    WriteVerb::Update => "update",
                }));
                assert!(target.read_operation_id.starts_with("get"));
            }
        }
    }

    #[test]
    fn merge_preserves_unspecified_fields() {
        let before = json!({"name": "branch", "vlan_id": 10, "subnet": "10.0.0.0/24"});
        let patch = json!({"vlan_id": 20});
        assert_eq!(
            merge_patch(&before, &patch),
            json!({"name": "branch", "vlan_id": 20, "subnet": "10.0.0.0/24"})
        );
    }

    #[test]
    fn merge_replaces_arrays_wholesale() {
        let before = json!({"servers": ["a", "b", "c"]});
        let patch = json!({"servers": ["z"]});
        assert_eq!(merge_patch(&before, &patch), json!({"servers": ["z"]}));
    }

    #[test]
    fn merge_deletes_on_null() {
        let before = json!({"name": "branch", "note": "temporary"});
        let patch = json!({"note": null});
        assert_eq!(merge_patch(&before, &patch), json!({"name": "branch"}));
    }

    #[test]
    fn merge_recurses_into_nested_objects() {
        let before = json!({"dhcpd": {"enabled": true, "lease": 3600}});
        let patch = json!({"dhcpd": {"lease": 7200}});
        assert_eq!(
            merge_patch(&before, &patch),
            json!({"dhcpd": {"enabled": true, "lease": 7200}})
        );
    }

    #[test]
    fn config_authority_is_refused_at_any_depth() {
        assert_eq!(
            reject_config_authority(&json!({"mist_configured": true})),
            Err(PatchError::MistConfigured)
        );
        assert_eq!(
            reject_config_authority(&json!({"switch": {"mist_configured": false}})),
            Err(PatchError::MistConfigured)
        );
        assert_eq!(
            reject_config_authority(&json!({"devices": [{"mist_configured": true}]})),
            Err(PatchError::MistConfigured)
        );
        assert_eq!(reject_config_authority(&json!({"name": "branch"})), Ok(()));
    }
}

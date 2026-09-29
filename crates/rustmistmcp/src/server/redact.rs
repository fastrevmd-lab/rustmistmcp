//! Mist-specific secret-field redaction, layered after `mecmcp_redact`.
//!
//! `mecmcp_redact`'s denylist is shared across every vendor MCP server this
//! company runs, so it only grows once a leak has already shipped somewhere.
//! These field names are specific to Mist's WAN edge and wireless config
//! shapes (BGP/OSPF routing secrets, RADIUS key-wrap material, WEP keys) and
//! are not yet in the upstream denylist. Call
//! [`redact_mist_extra_fields`] immediately after every
//! `mecmcp_redact::redact_json_value` call in this crate; once
//! `mecmcp-redact` picks these up (or this crate bumps to a rev that
//! already covers them), this module can shrink or go away.

use crate::server::wan_write::REDACTION_PLACEHOLDER;
use serde_json::Value;

/// Normalized (lowercased, separator-stripped) key names that are
/// secret-bearing wherever they appear, matched as a substring so
/// `auth_key`, `authKey`, and `auth_keys` (BGP/OSPF authentication
/// material) all match the same entry.
// "authkey" matches bgp_config.*.auth_key and ospf_areas.*.networks.*.auth_keys;
// "keywrap" matches radius_config.auth_servers[].keywrap_kek and .keywrap_mack.
const EXTRA_DENYLISTED_KEYS: &[&str] = &["authkey", "keywrap"];

/// Normalized key names that must match the whole key, not a substring.
/// `"keys"` alone would otherwise redact `passkeys`... this scopes it to the
/// exact field name `wlan.auth.keys` (WEP) uses, the same way
/// `mecmcp_redact::denylist` exact-matches the bare `"key"` field.
const EXTRA_DENYLISTED_EXACT_KEYS: &[&str] = &["keys"];

fn normalize(key: &str) -> String {
    key.chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect()
}

fn is_extra_denylisted_key(key: &str) -> bool {
    let normalized = normalize(key);
    EXTRA_DENYLISTED_EXACT_KEYS
        .iter()
        .any(|denied| normalized == *denied)
        || EXTRA_DENYLISTED_KEYS
            .iter()
            .any(|denied| normalized.contains(denied))
}

/// A denylisted key's value becomes the placeholder at every scalar leaf,
/// structure preserved -- mirrors `mecmcp_redact::json::redact_leaf` so an
/// array of WEP keys redacts to an array of placeholders (same length, not
/// collapsed to a single value) rather than losing shape.
fn redact_leaf(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, v)| (key.clone(), redact_leaf(v)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(redact_leaf).collect()),
        Value::Null => Value::Null,
        _ => Value::String(REDACTION_PLACEHOLDER.to_owned()),
    }
}

/// Redact Mist-specific secret-bearing fields in place, recursively.
///
/// Call this after `mecmcp_redact::redact_json_value` at every point a Mist
/// response reaches the model -- it is additive, not a replacement.
pub(crate) fn redact_mist_extra_fields(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, v) in map.iter_mut() {
                if is_extra_denylisted_key(key) {
                    *v = redact_leaf(v);
                } else {
                    redact_mist_extra_fields(v);
                }
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                redact_mist_extra_fields(item);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts_bgp_auth_key() {
        let mut v = json!({"bgp_config": {"peer1": {"auth_key": "s3cr3t-bgp"}}});
        redact_mist_extra_fields(&mut v);
        assert_eq!(v["bgp_config"]["peer1"]["auth_key"], REDACTION_PLACEHOLDER);
    }

    #[test]
    fn redacts_ospf_area_network_auth_keys() {
        let mut v = json!({
            "ospf_areas": {"0.0.0.0": {"networks": [{"network": "10.0.0.0/24", "auth_keys": ["s3cr3t-1"]}]}}
        });
        redact_mist_extra_fields(&mut v);
        assert_eq!(
            v["ospf_areas"]["0.0.0.0"]["networks"][0]["auth_keys"][0],
            REDACTION_PLACEHOLDER
        );
    }

    #[test]
    fn redacts_radius_keywrap_kek_and_mack() {
        let mut v = json!({
            "radius_config": {"auth_servers": [{"host": "198.51.100.10", "keywrap_kek": "kek-secret", "keywrap_mack": "mack-secret"}]}
        });
        redact_mist_extra_fields(&mut v);
        assert_eq!(
            v["radius_config"]["auth_servers"][0]["keywrap_kek"],
            REDACTION_PLACEHOLDER
        );
        assert_eq!(
            v["radius_config"]["auth_servers"][0]["keywrap_mack"],
            REDACTION_PLACEHOLDER
        );
        // Non-secret sibling fields must survive.
        assert_eq!(
            v["radius_config"]["auth_servers"][0]["host"],
            "198.51.100.10"
        );
    }

    #[test]
    fn redacts_wep_keys_array_preserving_shape() {
        let mut v =
            json!({"wlan": {"auth": {"type": "wep", "keys": ["ab12cd34ef", "11223344aa"]}}});
        redact_mist_extra_fields(&mut v);
        assert_eq!(v["wlan"]["auth"]["keys"][0], REDACTION_PLACEHOLDER);
        assert_eq!(v["wlan"]["auth"]["keys"][1], REDACTION_PLACEHOLDER);
        assert_eq!(v["wlan"]["auth"]["type"], "wep");
    }

    #[test]
    fn does_not_redact_unrelated_keys_field() {
        // "keys" is exact-matched, not substring-matched, so an unrelated
        // key containing "keys" as a suffix must survive.
        let mut v = json!({"monkeys": "not a secret"});
        redact_mist_extra_fields(&mut v);
        assert_eq!(v["monkeys"], "not a secret");
    }
}

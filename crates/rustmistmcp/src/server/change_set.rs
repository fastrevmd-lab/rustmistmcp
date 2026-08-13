//! The Mist change-set lifecycle: stage, inspect, approve, apply.
//!
//! The state machine, persistence and digests are `mecmcp-changeset`'s. What
//! belongs here is Mist-specific: which read produces the `before` state, how
//! an object is named as a concurrency key, and what verification means.

use crate::server::wan::WanObject;

/// Format an object as a change-set `device` key.
///
/// `ChangeSetRecord.device` is what `device_guard` locks on, so it is the
/// concurrency unit. Mist has no devices, so the object being changed serves:
/// two operators editing different networks proceed in parallel, and two edits
/// to the same network serialize. A create has no UUID yet, so all creates of
/// one object type share a key and serialize — deliberate and cheap.
///
/// Objects that reference each other are deliberately NOT serialized against
/// each other. Widening this key to compensate would trade a real, understood
/// limitation for a coarse lock nobody can reason about.
#[allow(dead_code)]
pub(crate) fn object_key(object: WanObject, object_id: Option<&str>) -> String {
    let name = match object {
        WanObject::Network => "network",
        WanObject::Service => "service",
        WanObject::ServicePolicy => "servicepolicy",
        WanObject::GatewayTemplate => "gatewaytemplate",
        WanObject::DeviceProfile => "deviceprofile",
    };
    match object_id {
        Some(id) => format!("{name}/{id}"),
        None => format!("{name}/new"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_key_names_the_object_not_the_org() {
        assert_eq!(
            object_key(
                WanObject::Network,
                Some("2b0f0000-0000-0000-0000-000000000001")
            ),
            "network/2b0f0000-0000-0000-0000-000000000001"
        );
        assert_eq!(
            object_key(WanObject::GatewayTemplate, Some("abc")),
            "gatewaytemplate/abc"
        );
    }

    #[test]
    fn creates_share_one_key_per_object_type() {
        assert_eq!(object_key(WanObject::Service, None), "service/new");
        assert_eq!(object_key(WanObject::Network, None), "network/new");
    }
}

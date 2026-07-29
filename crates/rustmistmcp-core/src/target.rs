//! Mist's temporary canonical organization and site target bridge for #91.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A malformed Mist organization or site subject.
#[derive(Debug, thiserror::Error)]
#[error("invalid Mist target: {0}")]
pub struct MistTargetError(&'static str);

/// A canonical opaque Mist authorization subject.
///
/// Targets can only be created through [`Self::org`], [`Self::site`], or
/// [`Self::parse`], each of which validates the canonical subject spelling.
///
/// ```compile_fail
/// use rustmistmcp_core::MistTarget;
///
/// let _ = MistTarget::Org("not-a-uuid".to_owned());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MistTarget(MistTargetKind, String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum MistTargetKind {
    Org,
    Site,
}

impl MistTarget {
    /// Construct a canonical organization target.
    ///
    /// # Errors
    /// Returns an error when `id` is not a lowercase, non-nil hyphenated UUID.
    pub fn org(id: impl AsRef<str>) -> Result<Self, MistTargetError> {
        let id = id.as_ref();
        if !is_canonical_uuid(id) {
            return Err(MistTargetError(
                "organization ID must be a canonical non-nil UUID",
            ));
        }
        Ok(Self(MistTargetKind::Org, id.to_owned()))
    }

    /// Construct a canonical site target.
    ///
    /// # Errors
    /// Returns an error when `id` is not a lowercase, non-nil hyphenated UUID.
    pub fn site(id: impl AsRef<str>) -> Result<Self, MistTargetError> {
        let id = id.as_ref();
        if !is_canonical_uuid(id) {
            return Err(MistTargetError("site ID must be a canonical non-nil UUID"));
        }
        Ok(Self(MistTargetKind::Site, id.to_owned()))
    }

    /// Parse an exact opaque `org/<uuid>` or `site/<uuid>` subject.
    ///
    /// # Errors
    /// Returns an error for every non-canonical subject spelling.
    pub fn parse(subject: &str) -> Result<Self, MistTargetError> {
        let Some((kind, id)) = subject.split_once('/') else {
            return Err(MistTargetError(
                "subject must have exactly one kind separator",
            ));
        };
        if id.contains('/') {
            return Err(MistTargetError(
                "subject must have exactly one kind separator",
            ));
        }
        match kind {
            "org" => Self::org(id),
            "site" => Self::site(id),
            _ => Err(MistTargetError("subject kind must be org or site")),
        }
    }

    /// Return the exact opaque subject used at the upstream grant seam.
    #[must_use]
    pub fn subject(&self) -> String {
        self.to_string()
    }

    /// Return the target UUID without its kind prefix.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.1
    }
}

impl fmt::Display for MistTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            MistTargetKind::Org => write!(formatter, "org/{}", self.1),
            MistTargetKind::Site => write!(formatter, "site/{}", self.1),
        }
    }
}

impl Serialize for MistTarget {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let subject = self.to_string();
        Self::parse(&subject).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&subject)
    }
}

impl<'de> Deserialize<'de> for MistTarget {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let subject = String::deserialize(deserializer)?;
        Self::parse(&subject).map_err(serde::de::Error::custom)
    }
}

pub(crate) fn is_canonical_uuid(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }
    let bytes = value.as_bytes();
    let mut contains_nonzero = false;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            if byte != b'-' {
                return false;
            }
        } else if !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte) {
            return false;
        } else if byte != b'0' {
            contains_nonzero = true;
        }
    }
    contains_nonzero
}

//! Exact per-token Mist write authority over catalog operations and targets.

use std::collections::BTreeSet;

use mecmcp_auth::{Grant, GrantError};
use serde::{Deserialize, Serialize};

use crate::{MistAction, MistTarget};

const MAX_GRANT_VALUES: usize = 256;
const MAX_OPERATION_ID_LEN: usize = 256;

/// Exact positive allowlists for Mist mutations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MistGrant {
    /// Exact catalog operation IDs.
    pub allowed_operations: Vec<String>,
    /// Exact catalog action classifications.
    pub actions: Vec<MistAction>,
    /// Exact canonical organization or site subjects.
    pub subjects: Vec<MistTarget>,
}

impl MistGrant {
    /// Whether an exact catalog operation ID is authorized.
    #[must_use]
    pub fn allows_operation(&self, operation_id: &str) -> bool {
        self.allowed_operations
            .iter()
            .any(|allowed| allowed == operation_id)
    }

    /// Whether an exact canonical Mist target is authorized.
    #[must_use]
    pub fn allows_target(&self, target: &MistTarget) -> bool {
        self.subjects.iter().any(|allowed| allowed == target)
    }
}

impl Grant for MistGrant {
    type Action = MistAction;

    fn allows_action(&self, action: Self::Action) -> bool {
        self.actions.contains(&action)
    }

    fn allows_subject(&self, subject: &str) -> bool {
        MistTarget::parse(subject).is_ok_and(|target| self.allows_target(&target))
    }

    fn validate(&self) -> Result<(), GrantError> {
        validate_list("allowed_operations", &self.allowed_operations)?;
        validate_list("actions", &self.actions)?;
        validate_list("subjects", &self.subjects)?;
        for subject in &self.subjects {
            MistTarget::parse(&subject.subject()).map_err(|error| {
                GrantError::Invalid(format!("subjects must be canonical Mist targets: {error}"))
            })?;
        }
        for operation_id in &self.allowed_operations {
            if operation_id.is_empty()
                || operation_id.len() > MAX_OPERATION_ID_LEN
                || operation_id.contains('\0')
                || operation_id.contains(char::is_whitespace)
            {
                return Err(GrantError::Invalid(
                    "operation IDs must be non-empty, at most 256 bytes, and contain no whitespace or null bytes".into(),
                ));
            }
        }
        Ok(())
    }
}

fn validate_list<T: Ord>(name: &str, values: &[T]) -> Result<(), GrantError> {
    if values.is_empty() || values.len() > MAX_GRANT_VALUES {
        return Err(GrantError::Invalid(format!(
            "{name} must contain 1-{MAX_GRANT_VALUES} values"
        )));
    }
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        return Err(GrantError::Invalid(format!(
            "{name} must not contain duplicates"
        )));
    }
    Ok(())
}

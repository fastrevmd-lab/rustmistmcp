//! Operation- and origin-bound opaque Mist pagination cursors.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::catalog::{MistOperation, PaginationMode};
use crate::{MistError, MistTarget};

const MAX_OPERATION_ID_BYTES: usize = 256;
const MAX_CURSOR_BYTES: usize = 4_096;
/// Maximum accepted hex-encoded continuation size at the MCP boundary.
pub const MAX_ENCODED_CURSOR_BYTES: usize = 262_144;

/// Borrowed canonical request context retained by a continuation.
pub type MistCursorRequestContext<'a> = (
    &'a BTreeMap<String, String>,
    &'a BTreeMap<String, serde_json::Value>,
    Option<&'a MistTarget>,
);

/// An opaque continuation value bound to one Mist operation and configured origin.
///
/// The serialized cursor is untrusted transport state. Every decoded binding
/// and request-context field is revalidated and reauthorized before use;
/// integrity protection is deferred to the shared transport seam.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "MistCursorWire")]
pub struct MistCursor {
    operation_id: String,
    origin: String,
    mode: PaginationMode,
    value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    context: Option<MistCursorContext>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MistCursorWire {
    operation_id: String,
    origin: String,
    mode: PaginationMode,
    value: String,
    #[serde(default)]
    context: Option<MistCursorContext>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MistCursorContext {
    path: BTreeMap<String, String>,
    query: BTreeMap<String, serde_json::Value>,
    target: Option<MistTarget>,
}

impl TryFrom<MistCursorWire> for MistCursor {
    type Error = String;

    fn try_from(value: MistCursorWire) -> Result<Self, Self::Error> {
        let origin = Url::parse(&value.origin).map_err(|_| "origin must be a URL".to_owned())?;
        let mut cursor = Self::new(value.operation_id, &origin, value.mode, value.value)
            .map_err(|error| error.to_string())?;
        cursor.context = value.context;
        cursor
            .validate_encoded_size()
            .map_err(|error| error.to_string())?;
        Ok(cursor)
    }
}

impl MistCursor {
    /// Bind a nonempty opaque value to a paginated operation at one origin.
    ///
    /// This constructor performs only syntax and size checks; catalog lookup is
    /// deliberately performed by [`Self::validate_for`].
    pub fn new(
        operation_id: String,
        origin: &Url,
        mode: PaginationMode,
        value: String,
    ) -> Result<Self, MistError> {
        if operation_id.is_empty() || operation_id.len() > MAX_OPERATION_ID_BYTES {
            return Err(MistError::InvalidCursor(
                "operation ID must contain 1-256 bytes".to_owned(),
            ));
        }
        if mode == PaginationMode::None {
            return Err(MistError::InvalidCursor(
                "pagination mode must not be none".to_owned(),
            ));
        }
        if value.is_empty() || value.len() > MAX_CURSOR_BYTES {
            return Err(MistError::InvalidCursor(
                "cursor value must contain 1-4096 bytes".to_owned(),
            ));
        }
        Ok(Self {
            operation_id,
            origin: origin.as_str().to_owned(),
            mode,
            value,
            context: None,
        })
    }

    /// Attach the canonical request context used to issue this continuation.
    ///
    /// The context is revalidated and reauthorized when the cursor is used; it
    /// is not treated as integrity-protected transport state.
    pub fn with_request_context(
        mut self,
        path: BTreeMap<String, String>,
        query: BTreeMap<String, serde_json::Value>,
        target: Option<MistTarget>,
    ) -> Result<Self, MistError> {
        self.context = Some(MistCursorContext {
            path,
            query,
            target,
        });
        self.validate_encoded_size()?;
        Ok(self)
    }

    /// Return the request context attached when this continuation was issued.
    #[must_use]
    pub fn request_context(&self) -> Option<MistCursorRequestContext<'_>> {
        self.context
            .as_ref()
            .map(|context| (&context.path, &context.query, context.target.as_ref()))
    }

    /// Return the bound catalog operation ID.
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Return the bound pagination mode.
    pub fn mode(&self) -> PaginationMode {
        self.mode
    }

    /// Verify that this cursor can continue `operation` at `origin`.
    pub fn validate_for(&self, operation: &MistOperation, origin: &Url) -> Result<(), MistError> {
        if self.operation_id != operation.operation_id {
            return Err(MistError::InvalidCursor(
                "cursor operation does not match request operation".to_owned(),
            ));
        }
        if self.origin != origin.as_str() {
            return Err(MistError::InvalidCursor(
                "cursor origin does not match request origin".to_owned(),
            ));
        }
        if self.mode != operation.pagination {
            return Err(MistError::InvalidCursor(
                "cursor pagination mode does not match request operation".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_encoded_size(&self) -> Result<(), MistError> {
        let serialized = serde_json::to_vec(self)
            .map_err(|_| MistError::InvalidCursor("cursor could not be serialized".to_owned()))?;
        if serialized.len().saturating_mul(2) > MAX_ENCODED_CURSOR_BYTES {
            return Err(MistError::InvalidCursor(
                "encoded cursor exceeds the 262144-byte bound".to_owned(),
            ));
        }
        Ok(())
    }
}

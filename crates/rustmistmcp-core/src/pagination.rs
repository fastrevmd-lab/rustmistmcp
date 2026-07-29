//! Operation- and origin-bound opaque Mist pagination cursors.

use serde::{Deserialize, Serialize};
use url::Url;

use crate::MistError;
use crate::catalog::{MistOperation, PaginationMode};

const MAX_OPERATION_ID_BYTES: usize = 256;
const MAX_CURSOR_BYTES: usize = 4_096;

/// An opaque continuation value bound to one Mist operation and configured origin.
///
/// The fields remain private so callers cannot change a cursor's binding after
/// it has been issued. Parsing response pagination data remains the future
/// shared-transport adapter's responsibility.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "MistCursorWire")]
pub struct MistCursor {
    operation_id: String,
    origin: String,
    mode: PaginationMode,
    value: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MistCursorWire {
    operation_id: String,
    origin: String,
    mode: PaginationMode,
    value: String,
}

impl TryFrom<MistCursorWire> for MistCursor {
    type Error = String;

    fn try_from(value: MistCursorWire) -> Result<Self, Self::Error> {
        let origin = Url::parse(&value.origin).map_err(|_| "origin must be a URL".to_owned())?;
        Self::new(value.operation_id, &origin, value.mode, value.value)
            .map_err(|error| error.to_string())
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
        })
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
}

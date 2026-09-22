//! Catalog-bound Mist request and response data-transfer objects.
//!
//! Validation here checks only Mist catalog data. It does not construct a URL,
//! encode a request, read a secret, decode a response, or enforce HTTP stream
//! limits; those shared transport duties remain blocked on mecmcp#90.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::catalog::{Catalog, MistOperation};
use crate::{MistCursor, MistError};

const MAX_OPERATION_ID_BYTES: usize = 256;
const MAX_PATH_VALUES: usize = 8;
const MAX_QUERY_VALUES: usize = 64;
const MAX_VALUE_DEPTH: usize = 32;
const MAX_VALUE_MEMBERS: usize = 1_024;
const MAX_VALUE_STRING_BYTES: usize = 32_768;
const MAX_RESPONSE_BODY_BYTES: usize = 524_288;
const MAX_RESPONSE_SERIALIZED_BYTES: usize = 1_048_576;

/// A structured, catalog-bound request for an injected Mist client.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MistRequest {
    /// Exact OpenAPI operation ID from the embedded Mist catalog.
    pub operation_id: String,
    /// Values for catalogued path parameters; no path expansion occurs here.
    #[serde(default)]
    pub path: BTreeMap<String, String>,
    /// JSON values for catalogued query parameters; no query encoding occurs here.
    #[serde(default)]
    pub query: BTreeMap<String, serde_json::Value>,
    /// A JSON request body, permitted only where the catalog declares JSON media.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json: Option<serde_json::Value>,
    /// An opaque continuation previously bound to this operation and origin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<MistCursor>,
}

/// A prebuilt result returned by an injected Mist client.
///
/// It does not imply that this crate performs HTTP response decoding or stream
/// bounding; a future shared-transport adapter will create these values.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MistResponse {
    /// The operation that produced this result.
    pub operation_id: String,
    /// The HTTP status supplied by the injected client.
    pub status: u16,
    /// The already-decoded or bounded response body supplied by that client.
    pub body: MistResponseBody,
    /// An optional opaque continuation supplied by that client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<MistCursor>,
}

/// A response representation supplied by an injected client.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum MistResponseBody {
    /// A JSON response already decoded by the supplied client.
    Json(serde_json::Value),
    /// A UTF-8 text response already decoded by the supplied client.
    Text(String),
    /// Bounded binary data supplied by the future shared transport.
    Binary(Vec<u8>),
    /// A declared no-content response.
    Empty,
}

impl MistRequest {
    /// Validate this request against one audited catalog and configured origin.
    ///
    /// The returned request is unchanged. This method never creates a network
    /// client or request; it only validates catalog-facing tool input.
    pub fn validate(self, catalog: &Catalog, origin: &Url) -> Result<Self, MistError> {
        validate_request_bounds(&self)?;
        let operation = catalog
            .operation(&self.operation_id)
            .ok_or_else(|| MistError::UnknownOperation(self.operation_id.clone()))?;

        validate_parameters(&self, operation, catalog)?;
        validate_json_body(&self, operation, catalog)?;
        if let Some(cursor) = &self.cursor {
            cursor.validate_for(operation, origin)?;
        }
        Ok(self)
    }
}

impl MistResponse {
    /// Validate this prebuilt response against one audited catalog and origin.
    ///
    /// This validates an already supplied DTO only. It does not decode an HTTP
    /// response or enforce a streaming byte limit.
    pub fn validate(self, catalog: &Catalog, origin: &Url) -> Result<Self, MistError> {
        let operation = catalog
            .operation(&self.operation_id)
            .ok_or_else(|| MistError::UnknownOperation(self.operation_id.clone()))?;
        let status = self.status.to_string();
        let responses =
            operation
                .responses
                .get(&status)
                .ok_or_else(|| MistError::InvalidResponse {
                    operation_id: self.operation_id.clone(),
                    reason: "status is not declared for operation".to_owned(),
                })?;
        validate_response_bounds(&self)?;
        validate_response_body(&self, responses, catalog)?;
        if let Some(cursor) = &self.cursor {
            cursor.validate_for(operation, origin)?;
        }
        Ok(self)
    }
}

fn validate_request_bounds(request: &MistRequest) -> Result<(), MistError> {
    if request.operation_id.is_empty() || request.operation_id.len() > MAX_OPERATION_ID_BYTES {
        return invalid(request, "operation ID must contain 1-256 bytes");
    }
    if request.path.len() > MAX_PATH_VALUES {
        return invalid(request, "path values exceed the Mist input bound of 8");
    }
    if request.query.len() > MAX_QUERY_VALUES {
        return invalid(request, "query values exceed the Mist input bound of 64");
    }
    for (name, value) in &request.path {
        if name.is_empty() || name.len() > MAX_OPERATION_ID_BYTES {
            return invalid(request, "path parameter names must contain 1-256 bytes");
        }
        if value.len() > MAX_VALUE_STRING_BYTES {
            return invalid(request, "path values must not exceed 32768 bytes");
        }
    }
    for name in request.query.keys() {
        if name.is_empty() || name.len() > MAX_OPERATION_ID_BYTES {
            return invalid(request, "query parameter names must contain 1-256 bytes");
        }
    }
    if let Some(json) = &request.json {
        validate_value_bounds(json, 0).map_err(|reason| MistError::InvalidRequest {
            operation_id: request.operation_id.clone(),
            reason,
        })?;
    }
    for value in request.query.values() {
        validate_value_bounds(value, 0).map_err(|reason| MistError::InvalidRequest {
            operation_id: request.operation_id.clone(),
            reason,
        })?;
    }
    Ok(())
}

fn validate_value_bounds(value: &serde_json::Value, depth: usize) -> Result<(), String> {
    if depth > MAX_VALUE_DEPTH {
        return Err("JSON value exceeds the Mist input depth bound of 32".to_owned());
    }
    match value {
        serde_json::Value::String(value) if value.len() > MAX_VALUE_STRING_BYTES => {
            Err("JSON strings must not exceed 32768 bytes".to_owned())
        }
        serde_json::Value::Array(values) => {
            if values.len() > MAX_VALUE_MEMBERS {
                return Err("JSON arrays must not exceed 1024 members".to_owned());
            }
            values
                .iter()
                .try_for_each(|value| validate_value_bounds(value, depth + 1))
        }
        serde_json::Value::Object(values) => {
            if values.len() > MAX_VALUE_MEMBERS {
                return Err("JSON objects must not exceed 1024 members".to_owned());
            }
            values.iter().try_for_each(|(name, value)| {
                if name.len() > MAX_OPERATION_ID_BYTES {
                    return Err("JSON object keys must not exceed 256 bytes".to_owned());
                }
                validate_value_bounds(value, depth + 1)
            })
        }
        _ => Ok(()),
    }
}

fn validate_parameters(
    request: &MistRequest,
    operation: &MistOperation,
    catalog: &Catalog,
) -> Result<(), MistError> {
    validate_parameter_set(request, operation, catalog, "path")?;
    validate_parameter_set(request, operation, catalog, "query")
}

fn validate_parameter_set(
    request: &MistRequest,
    operation: &MistOperation,
    catalog: &Catalog,
    location: &str,
) -> Result<(), MistError> {
    let supplied: BTreeSet<&str> = match location {
        "path" => request.path.keys().map(String::as_str).collect(),
        "query" => request.query.keys().map(String::as_str).collect(),
        _ => unreachable!("only catalogued request locations are validated"),
    };
    let declared: BTreeSet<&str> = operation
        .parameters
        .iter()
        .filter(|parameter| parameter.location == location)
        .map(|parameter| parameter.name.as_str())
        .collect();
    if let Some(extra) = supplied.difference(&declared).next() {
        return invalid(
            request,
            &format!("undeclared {location} parameter: {extra}"),
        );
    }
    for parameter in operation
        .parameters
        .iter()
        .filter(|parameter| parameter.location == location)
    {
        let value = match location {
            "path" => request
                .path
                .get(&parameter.name)
                .map(|value| serde_json::json!(value)),
            "query" => request.query.get(&parameter.name).cloned(),
            _ => None,
        };
        match value {
            Some(value) => validate_schema(
                request,
                catalog,
                &operation.operation_key,
                crate::catalog::SchemaSlot::RequestParameter {
                    location: location.to_owned(),
                    name: parameter.name.clone(),
                },
                &parameter.schema,
                &value,
            )?,
            None if parameter.required => {
                return invalid(
                    request,
                    &format!("missing required {location} parameter: {}", parameter.name),
                );
            }
            None => {}
        }
    }
    Ok(())
}

fn validate_json_body(
    request: &MistRequest,
    operation: &MistOperation,
    catalog: &Catalog,
) -> Result<(), MistError> {
    let Some(json) = &request.json else {
        if operation.request_body_required {
            return invalid(
                request,
                "operation requires an application/json request body",
            );
        }
        return Ok(());
    };
    let Some(schema) = operation.request_schemas.get("application/json") else {
        return invalid(
            request,
            "operation does not declare an application/json request body",
        );
    };
    validate_schema(
        request,
        catalog,
        &operation.operation_key,
        crate::catalog::SchemaSlot::RequestBody,
        schema,
        json,
    )
}

fn validate_schema(
    request: &MistRequest,
    catalog: &Catalog,
    operation: &str,
    slot: crate::catalog::SchemaSlot,
    schema: &serde_json::Value,
    value: &serde_json::Value,
) -> Result<(), MistError> {
    match schema_matches(catalog, operation, slot, schema, value, Direction::Request) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(details)) => invalid(
            request,
            &format!("value violates catalog schema:\n{}", details),
        ),
        Err(()) => invalid(request, "catalog schema compilation failed"),
    }
}

/// Which direction a body is travelling, and therefore how strictly its
/// vocabulary is judged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Direction {
    /// Outbound to Mist. Judged exactly as declared — an unknown enum member in
    /// something we are about to send is our bug, and rejecting it protects the
    /// upstream call.
    Request,
    /// Inbound from Mist. Structure is judged; vocabulary is not. See
    /// [`crate::catalog::relax_for_responses`] for what that means and why.
    Response,
}

/// Return the JSON type name of a value without exposing its content.
///
/// Used for validation errors to avoid leaking sensitive instance values into
/// audit logs while still providing diagnosable type information.
fn json_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Format a validation error kind without embedding the instance value.
///
/// Critical for audit redaction: this must never interpolate the actual value,
/// only its type. Device names, hostnames, and serials are redacted in audit
/// logs; a schema violation should not bypass that by writing the raw value.
fn format_validation_error_kind(
    kind: &jsonschema::error::ValidationErrorKind,
    actual_type: &str,
) -> String {
    use jsonschema::error::{TypeKind, ValidationErrorKind};
    match kind {
        ValidationErrorKind::Type { kind: type_kind } => {
            let expected = match type_kind {
                TypeKind::Single(t) => format!("[\"{}\"]", t),
                TypeKind::Multiple(types) => {
                    let type_list: Vec<String> =
                        types.iter().map(|t| format!("\"{}\"", t)).collect();
                    format!("[{}]", type_list.join(", "))
                }
            };
            format!("expected one of {}, got {}", expected, actual_type)
        }
        ValidationErrorKind::Enum { options } => {
            let count = options.as_array().map(|a| a.len()).unwrap_or(0);
            format!(
                "value ({}) not in enum (expected one of {} options)",
                actual_type, count
            )
        }
        ValidationErrorKind::AdditionalProperties { unexpected } => {
            format!(
                "unexpected properties: {}",
                unexpected
                    .iter()
                    .map(|s| format!("\"{}\"", s))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
        ValidationErrorKind::Required { property } => {
            format!("missing required property \"{}\"", property)
        }
        ValidationErrorKind::Format { format } => {
            format!(
                "value ({}) does not match format \"{}\"",
                actual_type, format
            )
        }
        ValidationErrorKind::Pattern { pattern } => {
            format!("value (string) does not match pattern \"{}\"", pattern)
        }
        ValidationErrorKind::MinLength { limit } => {
            format!("string length below minimum {}", limit)
        }
        ValidationErrorKind::MaxLength { limit } => {
            format!("string length exceeds maximum {}", limit)
        }
        ValidationErrorKind::Minimum { limit } => {
            format!("number below minimum {}", limit)
        }
        ValidationErrorKind::Maximum { limit } => {
            format!("number exceeds maximum {}", limit)
        }
        ValidationErrorKind::MinItems { limit } => {
            format!("array has fewer than {} items", limit)
        }
        ValidationErrorKind::MaxItems { limit } => {
            format!("array has more than {} items", limit)
        }
        ValidationErrorKind::UniqueItems => "array contains duplicate items".to_owned(),
        ValidationErrorKind::MinProperties { limit } => {
            format!("object has fewer than {} properties", limit)
        }
        ValidationErrorKind::MaxProperties { limit } => {
            format!("object has more than {} properties", limit)
        }
        // For other kinds, provide a generic message with the keyword
        _ => format!(
            "validation failed: {} (type: {})",
            kind.keyword(),
            actual_type
        ),
    }
}

/// Validate one body against one declared schema.
///
/// The validation root embeds the components registry, so building it clones
/// ~2.2 MB and compiling a validator over it costs ~37 ms. Both were happening
/// per call, on the hot path, and being dropped at the end of it (#59). The
/// catalog is immutable after load, so the compiled validator is memoised
/// against `(direction, operation, schema index)` and the root is built only on
/// a miss — the closure below does not run on a hit.
///
/// Returns `Ok(Ok(()))` on successful validation, `Ok(Err(details))` when
/// validation fails with field-level error details, or `Err(())` when the
/// schema itself does not compile.
fn schema_matches(
    catalog: &Catalog,
    operation: &str,
    slot: crate::catalog::SchemaSlot,
    schema: &serde_json::Value,
    value: &serde_json::Value,
    direction: Direction,
) -> Result<Result<(), String>, ()> {
    let validator = catalog.cached_validator(operation, slot, || match direction {
        Direction::Request => serde_json::json!({
            "components": catalog.components,
            "allOf": [schema],
        }),
        Direction::Response => {
            let mut schema = schema.clone();
            crate::catalog::relax_for_responses(&mut schema);
            serde_json::json!({
                "components": catalog.relaxed_components(),
                "allOf": [schema],
            })
        }
    })?;

    let mut errors_iter = validator.iter_errors(value);
    if let Some(_first_error) = errors_iter.next() {
        const MAX_ERRORS_SHOWN: usize = 5;
        // Collect up to MAX_ERRORS_SHOWN errors (we already have the first one)
        let error_list: Vec<String> = std::iter::once(_first_error)
            .chain(errors_iter)
            .take(MAX_ERRORS_SHOWN)
            .map(|error| {
                let path = if error.instance_path().is_empty() {
                    "(root)".to_owned()
                } else {
                    error.instance_path().to_string()
                };
                // Get the JSON type of the actual value (not the value itself)
                let actual_type = json_type_name(error.instance());
                // Format error based on kind without embedding instance value
                let description = format_validation_error_kind(error.kind(), actual_type);
                format!("  - field {}: {}", path, description)
            })
            .collect();

        let total_errors = error_list.len();
        let mut message = error_list.join("\n");

        // The iterator was capped at MAX_ERRORS_SHOWN, but we don't know if
        // there were more. The best we can do is note when we hit the cap.
        if total_errors == MAX_ERRORS_SHOWN {
            message.push_str(&format!(
                "\n  ... (showing first {} of potentially more errors)",
                MAX_ERRORS_SHOWN
            ));
        }

        Ok(Err(message))
    } else {
        Ok(Ok(()))
    }
}

fn validate_response_bounds(response: &MistResponse) -> Result<(), MistError> {
    if response.operation_id.is_empty() || response.operation_id.len() > MAX_OPERATION_ID_BYTES {
        return invalid_response(response, "operation ID must contain 1-256 bytes");
    }
    match &response.body {
        MistResponseBody::Json(value) => {
            validate_value_bounds(value, 0).map_err(|reason| MistError::InvalidResponse {
                operation_id: response.operation_id.clone(),
                reason,
            })?;
        }
        MistResponseBody::Text(value) if value.len() > MAX_RESPONSE_BODY_BYTES => {
            return invalid_response(response, "text body exceeds the 524288-byte DTO bound");
        }
        MistResponseBody::Binary(value) if value.len() > MAX_RESPONSE_BODY_BYTES => {
            return invalid_response(response, "binary body exceeds the 524288-byte DTO bound");
        }
        MistResponseBody::Text(_) | MistResponseBody::Binary(_) | MistResponseBody::Empty => {}
    }
    let serialized = serde_json::to_vec(response).map_err(|_| MistError::InvalidResponse {
        operation_id: response.operation_id.clone(),
        reason: "response DTO could not be serialized".to_owned(),
    })?;
    if serialized.len() > MAX_RESPONSE_SERIALIZED_BYTES {
        return invalid_response(
            response,
            "response exceeds the 1048576-byte serialized DTO bound",
        );
    }
    Ok(())
}

fn validate_response_body(
    response: &MistResponse,
    responses: &BTreeMap<String, serde_json::Value>,
    catalog: &Catalog,
) -> Result<(), MistError> {
    if responses.is_empty() {
        return if matches!(response.body, MistResponseBody::Empty) {
            Ok(())
        } else {
            invalid_response(
                response,
                "declared no-content status requires an empty body",
            )
        };
    }
    let result = match &response.body {
        MistResponseBody::Empty => Err("declared response media requires a body".to_owned()),
        MistResponseBody::Json(value) => {
            // The media type is kept, not dropped: it is half the cache key.
            let schemas: Vec<_> = responses
                .iter()
                .filter(|(media, _)| is_json_media(media))
                .collect();
            if schemas.is_empty() {
                Err("JSON body does not match declared response media".to_owned())
            } else {
                let mut all_errors = Vec::new();
                let mut any_passed = false;

                for (media, schema) in &schemas {
                    match schema_matches(
                        catalog,
                        &response.operation_id,
                        crate::catalog::SchemaSlot::ResponseBody {
                            status: response.status.to_string(),
                            media: (*media).clone(),
                        },
                        schema,
                        value,
                        Direction::Response,
                    ) {
                        Ok(Ok(())) => {
                            any_passed = true;
                            break;
                        }
                        Ok(Err(details)) => {
                            all_errors.push(format!("Schema for {}:\n{}", media, details));
                        }
                        Err(()) => {
                            all_errors.push(format!("Schema for {}: compilation failed", media));
                        }
                    }
                }

                if any_passed {
                    Ok(())
                } else if all_errors.is_empty() {
                    Err(
                        "JSON body violates declared response schema (no details available)"
                            .to_owned(),
                    )
                } else {
                    Err(format!(
                        "JSON body violates declared response schema:\n{}",
                        all_errors.join("\n\n")
                    ))
                }
            }
        }
        MistResponseBody::Text(_) if responses.keys().any(|media| media.starts_with("text/")) => {
            Ok(())
        }
        MistResponseBody::Text(_) => {
            Err("text body does not match declared response media".to_owned())
        }
        MistResponseBody::Binary(_) if responses.contains_key("application/octet-stream") => Ok(()),
        MistResponseBody::Binary(_) => {
            Err("binary body does not match declared response media".to_owned())
        }
    };
    result.map_err(|reason| MistError::InvalidResponse {
        operation_id: response.operation_id.clone(),
        reason,
    })
}

fn is_json_media(media: &str) -> bool {
    media.starts_with("application/") && media.contains("json")
}

fn invalid<T>(request: &MistRequest, reason: &str) -> Result<T, MistError> {
    Err(MistError::InvalidRequest {
        operation_id: request.operation_id.clone(),
        reason: reason.to_owned(),
    })
}

fn invalid_response<T>(response: &MistResponse, reason: &str) -> Result<T, MistError> {
    Err(MistError::InvalidResponse {
        operation_id: response.operation_id.clone(),
        reason: reason.to_owned(),
    })
}

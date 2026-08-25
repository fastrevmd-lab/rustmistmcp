//! Audited Mist OpenAPI operation catalog.
//!
//! The catalog is generated from the vendored official snapshot. It is data,
//! not a generated MCP tool surface; callers must select an operation by its
//! catalogued operation ID and use the later Mist-specific request adapter.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Errors returned while loading an audited operation catalog.
#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    /// The generated JSON was not valid for the catalog data model.
    #[error("invalid generated catalog JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// A generated catalog record violated an invariant required for safe use.
    #[error("invalid generated catalog: {0}")]
    Invalid(String),
}

/// Source provenance for a vendored Mist OpenAPI snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MistCatalogSource {
    /// Canonical upstream raw-document URL.
    pub url: String,
    /// Audited immutable upstream revision.
    pub revision: String,
    /// SHA-256 of the exact vendored source bytes.
    pub sha256: String,
    /// OpenAPI document version.
    pub openapi_version: String,
    /// Mist API version from the source document.
    pub api_version: String,
}

/// Catalog classification used to select the MCP authorization path.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MistCapability {
    /// Non-sensitive GET operation.
    OrdinaryRead,
    /// Sensitive GET operation requiring the privileged read dispatcher.
    PrivilegedRead,
    /// Resource-creating mutation.
    Create,
    /// Resource-updating mutation.
    Update,
    /// Resource-deleting mutation.
    Delete,
    /// Operational command mutation.
    Execute,
}

/// Grant action; exactly the six catalog security classifications.
pub type MistAction = MistCapability;

/// Target shape implied by a catalogued path template.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetSelector {
    /// Operation is not scoped to an org, site, or MSP target.
    None,
    /// Operation contains an `org_id` path selector.
    Org,
    /// Operation contains a `site_id` path selector.
    Site,
    /// Operation contains an `msp_id` path selector.
    Msp,
}

/// Pagination form recognized by the later request adapter.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PaginationMode {
    /// The operation has no declared page cursor input.
    None,
    /// The operation declares `page` and/or `limit` query parameters.
    PageLimit,
    /// The operation declares a `search_after` query parameter.
    SearchAfter,
}

/// Post-mutation state verification policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationPolicy {
    /// No verification applies to read operations.
    None,
    /// The service acknowledgement is the only catalogued outcome currently.
    ApiAcknowledged,
    /// A later change adapter may issue a catalogued follow-up read.
    FollowUpRead,
}

/// Typed declaration of one OpenAPI parameter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MistParameter {
    /// Parameter name.
    pub name: String,
    /// OpenAPI parameter location.
    #[serde(rename = "in")]
    pub location: String,
    /// Whether the parameter is mandatory.
    pub required: bool,
    /// Complete canonical OpenAPI schema, including inline constraints.
    pub schema: serde_json::Value,
}

/// A single safe, catalogued Mist API operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MistOperation {
    /// Stable `METHOD path` operation identity.
    pub operation_key: String,
    /// OpenAPI operation ID.
    pub operation_id: String,
    /// Deterministically derived historical tool name.
    pub tool: String,
    /// HTTP method.
    pub method: String,
    /// Safe `/api/v1/` path template.
    pub path: String,
    /// First path segment after `/api/v1/`.
    pub scope: String,
    /// Source operation summary.
    pub summary: String,
    /// Source OpenAPI tags.
    pub openapi_tags: Vec<String>,
    /// Authorization capability classification.
    pub capability: MistCapability,
    /// Exact grant action classification.
    pub action: MistAction,
    /// Reviewed justification for the exact classification.
    pub classification_reason: String,
    /// Source-locked fingerprint of the policy row's OpenAPI operation.
    pub classification_source_fingerprint: String,
    /// Typed source parameter declarations.
    pub parameters: Vec<MistParameter>,
    /// Canonical target selectors inferred from the path template.
    pub target_selectors: Vec<TargetSelector>,
    /// Supported request media types.
    pub request_media_types: Vec<String>,
    /// Complete source request schemas keyed by media type.
    pub request_schemas: BTreeMap<String, serde_json::Value>,
    /// Whether OpenAPI requires a request body for this operation.
    pub request_body_required: bool,
    /// Source success-response media types.
    pub response_media_types: Vec<String>,
    /// Source response schemas keyed first by status and then media type.
    pub responses: BTreeMap<String, BTreeMap<String, serde_json::Value>>,
    /// Recognized pagination shape.
    pub pagination: PaginationMode,
    /// Mutation verification policy.
    pub verification: VerificationPolicy,
    /// Catalogued read operation used to verify a successful mutation.
    pub follow_up_operation_id: Option<String>,
    /// Reviewed predicate for a catalogued follow-up read.
    pub verification_predicate: Option<String>,
    /// Audited reason why a mutation has no catalogued follow-up read.
    pub verification_reason: Option<String>,
    /// Request encoding required by the operation.
    pub transport: String,
    /// SHA-256 over the canonical operation source record.
    pub source_fingerprint: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogDocument {
    catalog_version: u8,
    platform: String,
    source: MistCatalogSource,
    components: serde_json::Value,
    operations: Vec<MistOperation>,
    audit: CatalogAudit,
}

/// Frozen reference facts retained alongside the current source catalog.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogAudit {
    /// Frozen reference server commit.
    pub reference_commit: String,
    /// Current registered generated operation wrappers in the reference.
    pub operation_wrappers: u16,
    /// Reference meta-tool count.
    pub meta_tools: u8,
    /// Current source operations not present as frozen wrappers.
    pub missing_current_operations: u8,
    /// Frozen wrapper count with no current source operation.
    pub stale_unmatched_wrappers: u8,
    /// The excluded stale wrapper's derived name.
    pub stale_wrapper_tool: String,
    /// Audited request-media distribution.
    pub media_accounting: MediaAccounting,
}

/// Request media totals frozen by the parity audit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MediaAccounting {
    /// Operations accepting only JSON requests.
    pub json_only_operations: u16,
    /// Operations accepting only multipart requests.
    pub multipart_only_operations: u8,
    /// Operations accepting both JSON and multipart requests.
    pub mixed_media_operations: u8,
    /// JSON media entries across all operations.
    pub json_media_entries: u16,
    /// Multipart media entries across all operations.
    pub multipart_media_entries: u8,
}

/// Loaded catalog ready for catalog-backed dispatch.
#[derive(Clone, Debug)]
pub struct Catalog {
    /// Source provenance.
    pub source: MistCatalogSource,
    /// Complete resolvable OpenAPI components registry.
    pub components: serde_json::Value,
    /// `components` with response-only vocabulary constraints removed.
    ///
    /// Computed on first use and reused: the transform walks every component
    /// schema, and doing that per response would double the cost of an already
    /// expensive validation.
    relaxed_components: std::sync::OnceLock<serde_json::Value>,
    /// All current source operations, sorted by `operation_key`.
    pub operations: Vec<MistOperation>,
    /// Frozen reference discrepancy and media facts.
    pub audit: CatalogAudit,
    operation_index: BTreeMap<String, usize>,
}

/// The catalog compiled into this binary.
///
/// Deliberately a function rather than a `const`: naming 4.6 MB of JSON as a
/// `const` makes rustc serialise the whole value into this crate's metadata,
/// which grew `librustmistmcp_core.rmeta` from 519 KB to 10.3 MB and put that
/// cost on every downstream build and cache read. Behind a function the bytes
/// stay in the object file where they belong.
#[must_use]
pub fn embedded_catalog_json() -> &'static str {
    include_str!("../../../docs/mist-api/catalog.json")
}

/// Whether a parse recomputes every operation's `source_fingerprint`.
///
/// Verifying costs a second full parse of the document into
/// [`serde_json::Value`], which for the pinned catalog is roughly ten times
/// the 4.6 MB of JSON it comes from. That is worth paying for bytes whose
/// provenance is unknown, and not worth paying at every process start for
/// bytes that `include_str!` froze into the binary at compile time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fingerprints {
    /// Recompute and compare every fingerprint.
    Verify,
    /// Trust the fingerprints already in the document.
    Trust,
}

impl Catalog {
    /// Parse and validate generated catalog JSON.
    ///
    /// Every operation's `source_fingerprint` is recomputed and compared. Use
    /// this for any catalog whose bytes did not come from this binary.
    pub fn from_json(json: &str) -> Result<Self, CatalogError> {
        Self::parse(json, Fingerprints::Verify)
    }

    fn parse(json: &str, fingerprints: Fingerprints) -> Result<Self, CatalogError> {
        let document: CatalogDocument = serde_json::from_str(json)?;
        validate_document(&document)?;
        let raw = match fingerprints {
            Fingerprints::Verify => Some(serde_json::from_str::<serde_json::Value>(json)?),
            Fingerprints::Trust => None,
        };
        let mut ids = BTreeSet::new();
        let mut keys = BTreeSet::new();
        let mut tools = BTreeSet::new();
        let mut operation_index = BTreeMap::new();
        let mut previous_key: Option<&str> = None;
        for (index, operation) in document.operations.iter().enumerate() {
            if !ids.insert(&operation.operation_id)
                || !keys.insert(&operation.operation_key)
                || !tools.insert(&operation.tool)
            {
                return Err(CatalogError::Invalid(
                    "operation IDs, keys, and tools must be unique".into(),
                ));
            }
            validate_operation(operation, previous_key)?;
            if let Some(raw) = raw.as_ref() {
                let raw_operation = raw
                    .get("operations")
                    .and_then(serde_json::Value::as_array)
                    .and_then(|operations| operations.get(index))
                    .ok_or_else(|| {
                        CatalogError::Invalid("raw operation record is absent".into())
                    })?;
                let fingerprint = raw_operation_fingerprint(raw_operation)?;
                if fingerprint != operation.source_fingerprint {
                    return Err(CatalogError::Invalid(format!(
                        "invalid source fingerprint: {} expected {} got {}",
                        operation.operation_id, operation.source_fingerprint, fingerprint
                    )));
                }
            }
            previous_key = Some(&operation.operation_key);
            operation_index.insert(operation.operation_id.clone(), index);
        }
        validate_verification(&document.operations, &operation_index)?;
        Ok(Self {
            source: document.source,
            components: document.components,
            operations: document.operations,
            audit: document.audit,
            operation_index,
            relaxed_components: std::sync::OnceLock::new(),
        })
    }

    /// `components`, with the constraints that describe Juniper's *vocabulary*
    /// rather than the shape of a response removed.
    ///
    /// See [`relax_for_responses`] for what is dropped and why.
    #[must_use]
    pub fn relaxed_components(&self) -> &serde_json::Value {
        self.relaxed_components.get_or_init(|| {
            let mut relaxed = self.components.clone();
            relax_for_responses(&mut relaxed);
            relaxed
        })
    }

    /// Load the catalog checked into this crate's repository.
    ///
    /// These bytes are a compile-time constant, so their fingerprints cannot
    /// drift between builds and are trusted here rather than recomputed at
    /// every start. `catalog_fingerprints_are_verified_for_the_embedded_bytes`
    /// re-verifies the same bytes through [`Catalog::from_json`], so a catalog
    /// regenerated with a stale fingerprint still fails the build.
    pub fn embedded() -> Result<Self, CatalogError> {
        Self::parse(embedded_catalog_json(), Fingerprints::Trust)
    }

    /// Look up an operation by its OpenAPI operation ID.
    pub fn operation(&self, operation_id: &str) -> Option<&MistOperation> {
        self.operation_index
            .get(operation_id)
            .and_then(|index| self.operations.get(*index))
    }

    /// Derive a historical tool name using the frozen v1 transform.
    pub fn tool_name(operation_id: &str) -> Result<String, CatalogError> {
        if operation_id.is_empty()
            || !operation_id
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic)
            || !operation_id
                .as_bytes()
                .iter()
                .all(u8::is_ascii_alphanumeric)
        {
            return Err(CatalogError::Invalid(format!(
                "unsafe operation ID: {operation_id:?}"
            )));
        }
        let operation_id = operation_id
            .replace("OAuth2", "Oauth2")
            .replace("OAUTH2", "Oauth2")
            .replace("WiFi", "Wifi")
            .replace("WIFI", "Wifi")
            .replace("IoT", "Iot")
            .replace("IOT", "Iot")
            .replace("AOSCX", "Aoscx");
        let mut words: Vec<String> = Vec::new();
        let characters: Vec<char> = operation_id.chars().collect();
        let mut word = String::new();
        for (index, character) in characters.iter().copied().enumerate() {
            let previous = index
                .checked_sub(1)
                .and_then(|value| characters.get(value))
                .copied();
            let following = characters.get(index + 1).copied();
            let boundary = index > 0
                && character.is_uppercase()
                && previous.is_some_and(|value| {
                    value.is_lowercase()
                        || value.is_ascii_digit()
                        || (value.is_uppercase() && following.is_some_and(char::is_lowercase))
                });
            if boundary {
                words.push(word.to_lowercase());
                word.clear();
            }
            word.push(character);
        }
        if !word.is_empty() {
            words.push(word.to_lowercase());
        }
        let name = format!("mist_{}", words.join("_"));
        if !name.as_bytes().iter().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || *character == b'_'
        }) {
            return Err(CatalogError::Invalid(format!(
                "unsafe derived tool name: {name:?}"
            )));
        }
        Ok(name)
    }
}

fn validate_document(document: &CatalogDocument) -> Result<(), CatalogError> {
    if document.catalog_version != 1
        || document.platform != "mist"
        || document.source.url
            != "https://raw.githubusercontent.com/mistsys/mist_openapi/master/mist.openapi.json"
        || document.source.revision != "f3af90c696747d003b2d22fd15e7dcc94d288cac"
        || document.source.sha256
            != "2c3d769ef188bbce1b9db7a0774b5a10812d0a5bc11960b768de47b66bb88bbf"
        || document.source.openapi_version != "3.1.0"
        || document.source.api_version != "2607.1.0"
        || document.operations.len() != 1_059
    {
        return Err(CatalogError::Invalid(
            "unexpected catalog source or operation count".into(),
        ));
    }
    if document.audit.reference_commit != "2b91700b9049c2c27ce6a811a272f2ddfa8091e5"
        || document.audit.operation_wrappers != 1_050
        || document.audit.meta_tools != 3
        || document.audit.missing_current_operations != 10
        || document.audit.stale_unmatched_wrappers != 1
        || document.audit.stale_wrapper_tool != "mist_get_org_aos_register_cmd"
        || document.audit.media_accounting
            != (MediaAccounting {
                json_only_operations: 333,
                multipart_only_operations: 16,
                mixed_media_operations: 7,
                json_media_entries: 340,
                multipart_media_entries: 23,
            })
        || !document.components.is_object()
    {
        return Err(CatalogError::Invalid(
            "unexpected frozen audit or components registry".into(),
        ));
    }
    Ok(())
}

fn validate_operation(
    operation: &MistOperation,
    previous_key: Option<&str>,
) -> Result<(), CatalogError> {
    if previous_key.is_some_and(|previous| previous >= operation.operation_key.as_str())
        || !safe_path(&operation.path)
        || operation.operation_key != format!("{} {}", operation.method, operation.path)
        || scope_for_path(&operation.path).as_deref() != Some(operation.scope.as_str())
        || Catalog::tool_name(&operation.operation_id)? != operation.tool
        || !matches!(
            operation.method.as_str(),
            "GET" | "POST" | "PUT" | "PATCH" | "DELETE"
        )
        || operation.capability != operation.action
        || operation.classification_reason.is_empty()
        || !is_lower_hex_digest(&operation.classification_source_fingerprint)
        || !method_allows_action(&operation.method, operation.action)
        || operation.target_selectors != targets_for_path(&operation.path)
        || operation.request_media_types != canonical_request_media(&operation.request_schemas)?
        || (operation.request_body_required && operation.request_media_types.is_empty())
        || operation.transport != transport_for_media(&operation.request_media_types)?
        || operation.pagination != pagination_for_parameters(&operation.parameters)
        || response_media(&operation.responses) != operation.response_media_types
        || operation
            .parameters
            .iter()
            .any(|parameter| !parameter.schema.is_object())
        || operation
            .request_schemas
            .values()
            .any(|schema| !schema.is_object())
        || operation
            .responses
            .values()
            .any(|media| media.values().any(|schema| !schema.is_object()))
    {
        return Err(CatalogError::Invalid(format!(
            "invalid operation record: {}",
            operation.operation_id
        )));
    }
    if !is_lower_hex_digest(&operation.source_fingerprint) {
        return Err(CatalogError::Invalid(format!(
            "invalid source fingerprint syntax: {}",
            operation.operation_id
        )));
    }
    Ok(())
}

fn validate_verification(
    operations: &[MistOperation],
    index: &BTreeMap<String, usize>,
) -> Result<(), CatalogError> {
    for operation in operations {
        match operation.verification {
            VerificationPolicy::None
                if matches!(
                    operation.action,
                    MistAction::OrdinaryRead | MistAction::PrivilegedRead
                ) && operation.follow_up_operation_id.is_none()
                    && operation.verification_predicate.is_none()
                    && operation.verification_reason.is_none() => {}
            VerificationPolicy::FollowUpRead
                if operation.verification_reason.is_none()
                    && operation.verification_predicate.as_deref()
                        == Some("request_projection_equals_response") =>
            {
                let follow_up_id =
                    operation.follow_up_operation_id.as_deref().ok_or_else(|| {
                        CatalogError::Invalid(format!(
                            "missing follow-up read for {}",
                            operation.operation_id
                        ))
                    })?;
                let follow_up = index
                    .get(follow_up_id)
                    .and_then(|index| operations.get(*index))
                    .ok_or_else(|| {
                        CatalogError::Invalid(format!(
                            "unknown follow-up read for {}",
                            operation.operation_id
                        ))
                    })?;
                if follow_up.method != "GET" {
                    return Err(CatalogError::Invalid(format!(
                        "non-read follow-up for {}",
                        operation.operation_id
                    )));
                }
            }
            VerificationPolicy::ApiAcknowledged
                if operation.follow_up_operation_id.is_none()
                    && operation.verification_predicate.is_none()
                    && operation
                        .verification_reason
                        .as_deref()
                        .is_some_and(|reason| !reason.is_empty()) => {}
            _ => {
                return Err(CatalogError::Invalid(format!(
                    "invalid verification policy for {}",
                    operation.operation_id
                )));
            }
        }
    }
    Ok(())
}

fn safe_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/api/v1/") else {
        return false;
    };
    !rest.is_empty()
        && !path.contains(['?', '#'])
        && rest.split('/').all(|segment| {
            if segment.is_empty() || matches!(segment, "." | "..") {
                return false;
            }
            if let Some(parameter) = segment
                .strip_prefix('{')
                .and_then(|segment| segment.strip_suffix('}'))
            {
                return !parameter.is_empty()
                    && parameter
                        .as_bytes()
                        .first()
                        .is_some_and(u8::is_ascii_alphabetic)
                    && parameter
                        .as_bytes()
                        .iter()
                        .all(|character| character.is_ascii_alphanumeric() || *character == b'_');
            }
            !segment.contains(['{', '}'])
        })
}

fn scope_for_path(path: &str) -> Option<String> {
    path.strip_prefix("/api/v1/")
        .and_then(|rest| rest.split('/').next())
        .map(str::to_owned)
}

fn targets_for_path(path: &str) -> Vec<TargetSelector> {
    let mut targets = Vec::new();
    if path.contains("{org_id}") {
        targets.push(TargetSelector::Org);
    }
    if path.contains("{site_id}") {
        targets.push(TargetSelector::Site);
    }
    if path.contains("{msp_id}") {
        targets.push(TargetSelector::Msp);
    }
    if targets.is_empty() {
        targets.push(TargetSelector::None);
    }
    targets
}

fn method_allows_action(method: &str, action: MistAction) -> bool {
    match method {
        "GET" => matches!(
            action,
            MistAction::OrdinaryRead
                | MistAction::PrivilegedRead
                | MistAction::Update
                | MistAction::Execute
        ),
        "PUT" | "PATCH" => matches!(action, MistAction::Update | MistAction::Execute),
        "DELETE" => action == MistAction::Delete,
        "POST" => matches!(
            action,
            MistAction::Create | MistAction::Update | MistAction::Delete | MistAction::Execute
        ),
        _ => false,
    }
}

fn canonical_request_media(
    schemas: &BTreeMap<String, serde_json::Value>,
) -> Result<Vec<String>, CatalogError> {
    let media: Vec<String> = schemas.keys().cloned().collect();
    if media
        .iter()
        .any(|media| media != "application/json" && media != "multipart/form-data")
    {
        return Err(CatalogError::Invalid("unsupported request media".into()));
    }
    Ok(media)
}

fn transport_for_media(media: &[String]) -> Result<&'static str, CatalogError> {
    match media {
        [] => Ok("none"),
        [json] if json == "application/json" => Ok("json"),
        [multipart] if multipart == "multipart/form-data" => Ok("multipart"),
        [json, multipart] if json == "application/json" && multipart == "multipart/form-data" => {
            Ok("content_type_select")
        }
        _ => Err(CatalogError::Invalid(
            "unsupported request-media combination".into(),
        )),
    }
}

fn pagination_for_parameters(parameters: &[MistParameter]) -> PaginationMode {
    let names: BTreeSet<&str> = parameters
        .iter()
        .filter(|parameter| parameter.location == "query")
        .map(|parameter| parameter.name.as_str())
        .collect();
    if names.contains("search_after") {
        PaginationMode::SearchAfter
    } else if names.contains("page") || names.contains("limit") {
        PaginationMode::PageLimit
    } else {
        PaginationMode::None
    }
}

fn response_media(
    responses: &BTreeMap<String, BTreeMap<String, serde_json::Value>>,
) -> Vec<String> {
    responses
        .values()
        .flat_map(|media| media.keys().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn is_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|character| character.is_ascii_digit() || (b'a'..=b'f').contains(character))
}

fn raw_operation_fingerprint(operation: &serde_json::Value) -> Result<String, CatalogError> {
    let mut value = operation.clone();
    value
        .as_object_mut()
        .ok_or_else(|| CatalogError::Invalid("operation serialization is not an object".into()))?
        .remove("source_fingerprint");
    let mut canonical = serde_json::to_vec(&canonical_json(value)).map_err(CatalogError::Json)?;
    canonical.push(b'\n');
    Ok(hex::encode(Sha256::digest(canonical)))
}

fn canonical_json(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(canonical_json).collect())
        }
        serde_json::Value::Object(values) => {
            let values: BTreeMap<_, _> = values
                .into_iter()
                .map(|(key, value)| (key, canonical_json(value)))
                .collect();
            serde_json::Value::Object(values.into_iter().collect())
        }
        value => value,
    }
}

/// Strip the constraints that pin Juniper's *vocabulary* rather than the
/// *shape* of a response.
///
/// Response validation exists to refuse a body that is malformed or hostile —
/// wrong container, wrong types where we will index. It is a poor mechanism for
/// pinning a vendor's vocabulary, because the vendor extends that vocabulary
/// unilaterally and every addition then becomes a total failure of the
/// operation rather than one unrecognised field.
///
/// Measured against the pinned document, the exposure is not marginal:
///
/// | Constraint | Occurrences |
/// |---|---|
/// | `additionalProperties: false` | 1103 |
/// | closed `enum` | 516 |
/// | non-nullable typed fields | 8746 (against only 460 nullable unions) |
///
/// Two live failures on a real tenant motivated this, both of the same kind —
/// the pinned spec is narrower than the API it describes:
///
/// - `getSelf` returned `views: ["org_admin"]`; `admin_privilege_view` is a
///   closed enum of eight values that does not include it.
/// - `getOrg` returned `msp_id: null`; the field is declared `"string"`, while
///   `alarmtemplate_id` in the same schema is declared `["string","null"]` — so
///   the spec is inconsistent about optionality rather than missing a convention.
///
/// Three relaxations, each covering an *additive* vendor change:
///
/// 1. `enum` is dropped — a new member is data, not a violation.
/// 2. `additionalProperties: false` is dropped — a new field is data too, and
///    this is the largest exposure of the three.
/// 3. Any declared `type` is widened to admit `null`, since an absent optional
///    field is routinely returned as null.
///
/// What deliberately survives: containers, and the declared types of the fields
/// that are present and non-null. A response that is structurally wrong is still
/// refused.
///
/// **Requests are not relaxed.** Rejecting an unknown enum member in something
/// we are about to *send* is correct — it protects the upstream call and catches
/// our own bugs — and nothing about vendor evolution argues otherwise.
pub(crate) fn relax_for_responses(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            map.remove("enum");
            if map.get("additionalProperties") == Some(&serde_json::Value::Bool(false)) {
                map.remove("additionalProperties");
            }
            widen_type_to_admit_null(map);
            for nested in map.values_mut() {
                relax_for_responses(nested);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                relax_for_responses(item);
            }
        }
        _ => {}
    }
}

/// Add `"null"` to a schema's declared `type`, leaving every other type intact.
fn widen_type_to_admit_null(map: &mut serde_json::Map<String, serde_json::Value>) {
    let Some(declared) = map.get("type") else {
        return;
    };
    let widened = match declared {
        serde_json::Value::String(name) if name != "null" => {
            Some(serde_json::json!([name, "null"]))
        }
        serde_json::Value::Array(names) if !names.iter().any(|n| n.as_str() == Some("null")) => {
            let mut widened = names.clone();
            widened.push(serde_json::Value::String("null".to_owned()));
            Some(serde_json::Value::Array(widened))
        }
        _ => None,
    };
    if let Some(widened) = widened {
        map.insert("type".to_owned(), widened);
    }
}

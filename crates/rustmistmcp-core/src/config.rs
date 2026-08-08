//! Strict singleton Mist profile configuration.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use url::{Host, Url};

const CONFIG_VERSION: u32 = 1;
const MAX_ALLOWED_ORGS: usize = 256;

/// Errors while loading or validating Mist profile metadata.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The configuration file could not be read.
    #[error("unable to read Mist configuration: {0}")]
    Read(#[source] std::io::Error),
    /// The configuration file was not valid strict JSON.
    #[error("unable to parse Mist configuration: {0}")]
    Parse(#[source] serde_json::Error),
    /// Credential-file metadata could not be inspected.
    #[error("unable to inspect Mist credential file: {0}")]
    CredentialMetadata(#[source] std::io::Error),
    /// A configuration value did not meet the singleton-profile contract.
    #[error("invalid Mist configuration: {0}")]
    Invalid(&'static str),
}

/// One strict version-one Mist profile.
///
/// The credential file is validated as metadata only. Its contents are never
/// read here; loading the API token remains blocked on the shared #90 seam.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MistConfig {
    /// Configuration format version. Only version one is supported.
    pub version: u32,
    /// HTTPS regional Mist API root.
    pub endpoint: String,
    /// Absolute, regular mode-0600 API-token file.
    pub credential_file: PathBuf,
    /// Exact organization UUIDs visible to this profile.
    pub allowed_orgs: Vec<String>,
}

impl MistConfig {
    /// Read, deserialize, and validate a strict Mist profile.
    ///
    /// # Errors
    /// Returns a distinct error for configuration I/O, JSON parsing,
    /// credential metadata inspection, and invalid values.
    pub fn from_path(path: &Path) -> Result<Self, ConfigError> {
        let bytes = fs::read(path).map_err(ConfigError::Read)?;
        let config: Self = serde_json::from_slice(&bytes).map_err(ConfigError::Parse)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate the profile without loading its credential contents.
    ///
    /// # Errors
    /// Returns an error when a value is not permitted by the v1 profile
    /// contract or the credential path has unsafe metadata.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.version != CONFIG_VERSION {
            return Err(ConfigError::Invalid("unsupported config version"));
        }
        self.base_url()?;
        validate_credential_file(&self.credential_file)?;
        validate_allowed_orgs(&self.allowed_orgs)
    }

    /// Parse the configured HTTPS root for later Mist-specific request joining.
    pub(crate) fn base_url(&self) -> Result<Url, ConfigError> {
        validate_mist_endpoint(&self.endpoint)
    }
}

/// Validate and parse one HTTPS Mist regional API root.
///
/// This is the single endpoint validator shared by configuration loading and
/// public handler construction.
pub fn validate_mist_endpoint(endpoint: &str) -> Result<Url, ConfigError> {
    let url =
        Url::parse(endpoint).map_err(|_| ConfigError::Invalid("endpoint must be a valid URL"))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || url.port().is_some()
    {
        return Err(ConfigError::Invalid(
            "endpoint must be an HTTPS Mist API root",
        ));
    }
    let Some(Host::Domain(host)) = url.host() else {
        return Err(ConfigError::Invalid(
            "endpoint host must be a Mist API domain",
        ));
    };
    if !is_mist_regional_host(host) {
        return Err(ConfigError::Invalid(
            "endpoint host must be a Mist API regional domain",
        ));
    }
    Ok(url)
}

fn is_mist_regional_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("api.mist.com") {
        return true;
    }
    let labels: Vec<_> = host.split('.').collect();
    labels.len() == 4
        && labels[0].eq_ignore_ascii_case("api")
        && !labels[1].is_empty()
        && labels[2].eq_ignore_ascii_case("mist")
        && labels[3].eq_ignore_ascii_case("com")
}

fn validate_credential_file(path: &Path) -> Result<(), ConfigError> {
    if !path.is_absolute() {
        return Err(ConfigError::Invalid(
            "credential file must be an absolute path",
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(ConfigError::CredentialMetadata)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(ConfigError::Invalid(
            "credential file must be a regular non-symlink file",
        ));
    }
    #[cfg(unix)]
    if std::os::unix::fs::MetadataExt::mode(&metadata) & 0o777 != 0o600 {
        return Err(ConfigError::Invalid(
            "credential file permissions must be exactly 0600",
        ));
    }
    Ok(())
}

fn validate_allowed_orgs(allowed_orgs: &[String]) -> Result<(), ConfigError> {
    if allowed_orgs.is_empty() || allowed_orgs.len() > MAX_ALLOWED_ORGS {
        return Err(ConfigError::Invalid(
            "allowed_orgs must contain 1-256 organizations",
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for org in allowed_orgs {
        if !crate::target::is_canonical_uuid(org) {
            return Err(ConfigError::Invalid(
                "allowed_orgs must contain canonical non-nil UUIDs",
            ));
        }
        if !seen.insert(org) {
            return Err(ConfigError::Invalid(
                "allowed_orgs must not contain duplicates",
            ));
        }
    }
    Ok(())
}

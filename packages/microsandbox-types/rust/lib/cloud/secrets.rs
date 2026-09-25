//! Cloud secret-substitution wire contracts and domain conversions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::compat;
use crate::domain::{
    HostPattern, SecretEntry, SecretSubstitution, SecretViolationAction, SecretsConfig,
};
use crate::modify::SecretSource;
use crate::secret::{
    SecretDisposition, SecretMetadata, SecretRotationRequest, SecretRotationResult,
};

//--------------------------------------------------------------------------------------------------
// Types: Secrets
//--------------------------------------------------------------------------------------------------

/// Secret-substitution config for the cloud API. Twin of domain [`SecretsConfig`].
#[derive(Debug, Clone, Default, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudSecretsConfig {
    /// Secrets to inject.
    #[serde(default)]
    pub entries: Vec<CloudSecretEntry>,
    /// Default placeholder passthrough hosts, including for secrets added later.
    /// A per-secret violation action overrides this default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passthrough_hosts: Option<Vec<CloudHostPattern>>,
    /// Default action when a placeholder leaks to a disallowed host.
    #[serde(default)]
    pub violation_action: CloudViolationAction,
}

/// A single cloud secret entry. Twin of domain [`SecretEntry`].
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudSecretEntry {
    /// Environment variable name exposed to the sandbox.
    pub env_var: String,
    /// The secret value (empty when `source` carries a reference instead).
    #[serde(default)]
    pub value: String,
    /// Host-side source resolved into `value` at spawn time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<CloudSecretSource>,
    /// Explicit placeholder the sandbox sees instead of the real value.
    ///
    /// The field must be present on the wire. SDK builders may materialize a
    /// concrete default before serialization. Validation rejects empty,
    /// oversized, or line-breaking values.
    pub placeholder: String,
    /// Hosts allowed to receive this secret.
    #[serde(default)]
    pub allowed_hosts: Vec<CloudHostPattern>,
    /// Where the secret may be injected.
    #[serde(default)]
    pub substitution: SecretSubstitution,
    /// Hosts allowed to receive the placeholder unchanged.
    #[serde(default)]
    pub passthrough_hosts: Vec<CloudHostPattern>,
    /// Per-secret violation action overriding the config default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub violation_action: Option<CloudViolationAction>,
    /// Require verified TLS identity before substituting (default: true).
    #[serde(default)]
    #[cfg_attr(feature = "utoipa", schema(default = true))]
    pub require_tls_identity: bool,
}

/// Host-side source for a cloud secret. Twin of [`SecretSource`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CloudSecretSource {
    /// Read from a host environment variable at apply time.
    Env {
        /// Host environment variable name.
        var: String,
    },
    /// Read from a host-side secret store reference.
    Store {
        /// Store-specific secret reference.
        reference: String,
    },
}

/// Host allowlist pattern for cloud secrets. Twin of [`HostPattern`], with the
/// domain's scalar variants normalized to `{ value }` for a uniform union.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CloudHostPattern {
    /// Exact hostname match.
    Exact {
        /// Hostname to match exactly.
        value: String,
    },
    /// Wildcard match (e.g. `*.openai.com`).
    Wildcard {
        /// Wildcard pattern.
        value: String,
    },
    /// Any host (dangerous — the secret can be exfiltrated).
    Any,
}

/// Action on a cloud secret violation. Twin of [`SecretViolationAction`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CloudViolationAction {
    /// Block the request silently.
    Block,
    /// Block and log (default).
    #[default]
    BlockAndLog,
    /// Block and terminate the sandbox.
    BlockAndTerminate,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<'de> Deserialize<'de> for CloudSecretsConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        compat::cloud::deserialize_secrets_config(deserializer)
    }
}

impl<'de> Deserialize<'de> for CloudSecretEntry {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        compat::cloud::deserialize_secret_entry(deserializer)
    }
}

//--------------------------------------------------------------------------------------------------
// Conversions: Secrets
//--------------------------------------------------------------------------------------------------

impl From<HostPattern> for CloudHostPattern {
    fn from(pattern: HostPattern) -> Self {
        match pattern {
            HostPattern::Exact(value) => Self::Exact { value },
            HostPattern::Wildcard(value) => Self::Wildcard { value },
            HostPattern::Any => Self::Any,
        }
    }
}

impl From<CloudHostPattern> for HostPattern {
    fn from(pattern: CloudHostPattern) -> Self {
        match pattern {
            CloudHostPattern::Exact { value } => Self::Exact(value),
            CloudHostPattern::Wildcard { value } => Self::Wildcard(value),
            CloudHostPattern::Any => Self::Any,
        }
    }
}

impl From<SecretViolationAction> for CloudViolationAction {
    fn from(action: SecretViolationAction) -> Self {
        match action {
            SecretViolationAction::Block => Self::Block,
            SecretViolationAction::BlockAndLog => Self::BlockAndLog,
            SecretViolationAction::BlockAndTerminate => Self::BlockAndTerminate,
        }
    }
}

impl From<CloudViolationAction> for SecretViolationAction {
    fn from(action: CloudViolationAction) -> Self {
        match action {
            CloudViolationAction::Block => Self::Block,
            CloudViolationAction::BlockAndLog => Self::BlockAndLog,
            CloudViolationAction::BlockAndTerminate => Self::BlockAndTerminate,
        }
    }
}

impl From<SecretSource> for CloudSecretSource {
    fn from(source: SecretSource) -> Self {
        match source {
            SecretSource::Env { var } => Self::Env { var },
            SecretSource::Store { reference } => Self::Store { reference },
        }
    }
}

impl From<CloudSecretSource> for SecretSource {
    fn from(source: CloudSecretSource) -> Self {
        match source {
            CloudSecretSource::Env { var } => Self::Env { var },
            CloudSecretSource::Store { reference } => Self::Store { reference },
        }
    }
}

impl From<SecretEntry> for CloudSecretEntry {
    fn from(entry: SecretEntry) -> Self {
        Self {
            env_var: entry.env_var,
            value: entry.value.to_string(),
            source: entry.source.map(Into::into),
            placeholder: entry.placeholder,
            allowed_hosts: entry.allowed_hosts.into_iter().map(Into::into).collect(),
            substitution: entry.substitution,
            passthrough_hosts: entry
                .passthrough_hosts
                .into_iter()
                .map(Into::into)
                .collect(),
            violation_action: entry.violation_action.map(Into::into),
            require_tls_identity: entry.require_tls_identity,
        }
    }
}

impl From<CloudSecretEntry> for SecretEntry {
    fn from(entry: CloudSecretEntry) -> Self {
        Self {
            env_var: entry.env_var,
            value: Zeroizing::new(entry.value),
            source: entry.source.map(Into::into),
            placeholder: entry.placeholder,
            allowed_hosts: entry.allowed_hosts.into_iter().map(Into::into).collect(),
            substitution: entry.substitution,
            passthrough_hosts: entry
                .passthrough_hosts
                .into_iter()
                .map(Into::into)
                .collect(),
            violation_action: entry.violation_action.map(Into::into),
            require_tls_identity: entry.require_tls_identity,
        }
    }
}

impl From<SecretsConfig> for CloudSecretsConfig {
    fn from(config: SecretsConfig) -> Self {
        Self {
            entries: config.secrets.into_iter().map(Into::into).collect(),
            passthrough_hosts: config
                .passthrough_hosts
                .map(|hosts| hosts.into_iter().map(Into::into).collect()),
            violation_action: config.violation_action.into(),
        }
    }
}

impl From<CloudSecretsConfig> for SecretsConfig {
    fn from(config: CloudSecretsConfig) -> Self {
        Self {
            secrets: config.entries.into_iter().map(Into::into).collect(),
            passthrough_hosts: config
                .passthrough_hosts
                .map(|hosts| hosts.into_iter().map(Into::into).collect()),
            violation_action: config.violation_action.into(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Types: Metadata
//--------------------------------------------------------------------------------------------------

/// One secret's metadata, as the listing endpoint publishes it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudSecretMetadata {
    /// The configured env var name, and the only identifier the contract
    /// exposes.
    pub name: String,
    /// Opaque current version token. It carries no ordering and decodes to
    /// nothing; the only operation defined on it is equality. Send it back as
    /// the `version` field of the next conditional update.
    pub version: String,
    /// The store's own timestamp for this version, never a local clock.
    #[cfg_attr(feature = "ts", ts(type = "string"))]
    pub updated_at: DateTime<Utc>,
}

/// Envelope for the metadata list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudSecretMetadataList {
    /// One entry per configured secret, ordered by name.
    pub data: Vec<CloudSecretMetadata>,
}

//--------------------------------------------------------------------------------------------------
// Types: Rotation
//--------------------------------------------------------------------------------------------------

/// The rotation request body.
///
/// `Debug` is implemented by hand to redact the value - the derive would print
/// it, and secret material must never reach a log.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudSecretRotationRequest {
    /// New plaintext, at most 64 KiB of UTF-8 and never empty.
    pub value: String,
    /// Opaque version token the write is conditional on, as published by the
    /// metadata listing or a previous rotation result. Absent means no
    /// precondition was supplied, which the server refuses rather than writing
    /// unconditionally over a concurrent rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl std::fmt::Debug for CloudSecretRotationRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CloudSecretRotationRequest")
            .field("value", &"[REDACTED]")
            .field("version", &self.version)
            .finish()
    }
}

/// Public status of a rotation operation. There is no `queued`: a rotation is
/// admitted and dispatched inside one request.
///
/// This answers *is the operation finished?*, which drives whether the caller
/// polls again. It is the secret-rotation counterpart of
/// [`CloudSnapshotOperationStatus`], not a statement about the running VM -
/// for that, see [`CloudSecretDisposition`].
///
/// [`CloudSnapshotOperationStatus`]: super::CloudSnapshotOperationStatus
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum CloudSecretOperationStatus {
    /// Still active; carries neither result nor error.
    InProgress,
    /// Durably committed; carries only the result.
    Succeeded,
    /// Could not be established as successful; carries only a sanitized error.
    /// This does **not** assert that the store rolled anything back.
    Failed,
}

/// How far the committed version got toward the running VM.
///
/// Named for [`ModificationDisposition`], which answers the same question one
/// layer down - *when or whether a planned change can take effect*. This
/// answers whether the caller must act; whether the *operation* has finished
/// is [`CloudSecretOperationStatus`], which nests alongside it in the same
/// response.
///
/// [`ModificationDisposition`]: crate::ModificationDisposition
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum CloudSecretDisposition {
    /// The authoritative runtime acknowledged it. Nothing to do.
    Applied,
    /// Durable, but not delivered live. A future start reads it.
    OnNextStart,
    /// Durable, but the current runtime could not be confirmed. Reassert the
    /// value or restart if immediate convergence matters.
    Unconfirmed,
}

/// The result of a succeeded rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudSecretRotationResult {
    /// Env var name that was rotated.
    pub name: String,
    /// Opaque token for the version the store committed. It is the
    /// precondition for the next conditional update, without another metadata
    /// read.
    pub version: String,
    /// How far the new version got toward the running runtime.
    ///
    /// The wire key stays `application`: this shape has shipped, so only the
    /// Rust-side name changed.
    #[serde(rename = "application")]
    pub disposition: CloudSecretDisposition,
}

/// Sanitized failure detail. Both fields are fixed constants chosen from a
/// closed set - never an upstream message, response body, or path.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudSecretRotationError {
    /// Stable machine-readable code.
    pub code: String,
    /// Fixed human-readable text for that code.
    pub message: String,
}

/// The operation envelope, mirroring [`CloudSnapshotOperation`].
///
/// [`CloudSnapshotOperation`]: super::CloudSnapshotOperation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudSecretRotationOperation {
    /// Server-generated operation id, issued only after acceptance. There is no
    /// caller-supplied identifier anywhere in this contract.
    pub id: String,
    /// Current operation status.
    pub status: CloudSecretOperationStatus,
    /// Present only when `status` is `succeeded`.
    #[serde(default)]
    pub result: Option<CloudSecretRotationResult>,
    /// Present only when `status` is `failed`.
    #[serde(default)]
    pub error: Option<CloudSecretRotationError>,
}

//--------------------------------------------------------------------------------------------------
// Conversions: Rotation
//--------------------------------------------------------------------------------------------------

impl From<CloudSecretMetadata> for SecretMetadata {
    fn from(metadata: CloudSecretMetadata) -> Self {
        Self {
            name: metadata.name,
            version: metadata.version,
            updated_at: metadata.updated_at,
        }
    }
}

impl From<SecretRotationRequest> for CloudSecretRotationRequest {
    fn from(request: SecretRotationRequest) -> Self {
        Self {
            value: request.value,
            version: request.version,
        }
    }
}

impl From<CloudSecretDisposition> for SecretDisposition {
    fn from(disposition: CloudSecretDisposition) -> Self {
        match disposition {
            CloudSecretDisposition::Applied => Self::Applied,
            CloudSecretDisposition::OnNextStart => Self::OnNextStart,
            CloudSecretDisposition::Unconfirmed => Self::Unconfirmed,
        }
    }
}

impl From<CloudSecretRotationResult> for SecretRotationResult {
    fn from(result: CloudSecretRotationResult) -> Self {
        Self {
            name: result.name,
            version: result.version,
            disposition: result.disposition.into(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Constants: Rotation
//--------------------------------------------------------------------------------------------------

/// Crockford base32 without `I`, `L`, `O` and `U`, so a rendered value survives
/// being read aloud or retyped without collapsing onto a different one.
const TOKEN_ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// Odd multiplier of a Knuth-style multiplicative permutation over `2^40`.
/// Odd means it is invertible modulo a power of two, which is what makes the
/// whole mapping injective.
const VERSION_MULTIPLIER: u64 = 0x0037_79B9_7F4B;

/// Additive offset, applied after the multiply so that version zero is not a
/// run of leading alphabet-zero characters.
const VERSION_OFFSET: u64 = 0x0005_DEEC_E66D;

/// Width of the permuted space. Forty bits render as exactly eight base32
/// characters, and cover every version a secret can reach.
const VERSION_BITS: u32 = 40;

/// Number of base32 characters in a rendered token.
const VERSION_DIGITS: usize = 8;

/// Fail-closed marker for a store version outside the token's supported
/// non-negative 40-bit domain. It is deliberately not token-shaped.
const INVALID_VERSION_TOKEN: &str = "invalid-secret-version";

//--------------------------------------------------------------------------------------------------
// Functions: Rotation
//--------------------------------------------------------------------------------------------------

/// Render a version as its wire token: `v` + eight base32 characters.
///
/// A bijective permutation over `2^40`: distinct versions render distinctly,
/// adjacent ones with no visible relationship. Equality is the only operation.
///
/// Versions outside that space (negative, or >= `2^40`) render to an unshaped
/// fail-closed marker that [`verify_secret_version`] never accepts.
pub fn secret_version(version: i64) -> String {
    if !(0..(1_i64 << VERSION_BITS)).contains(&version) {
        return INVALID_VERSION_TOKEN.to_owned();
    }

    let permuted = permute_version(version);

    let mut token = String::with_capacity(1 + VERSION_DIGITS);
    token.push('v');

    // Most significant digit first, so the rendering is stable across
    // platforms and independent of any integer-to-string formatting.
    for digit in (0..VERSION_DIGITS).rev() {
        let index = (permuted >> (digit as u32 * 5)) & 0b1_1111;
        token.push(TOKEN_ALPHABET[index as usize] as char);
    }

    token
}

/// Whether `token` has the shape this server issues, whatever version it names.
///
/// Failing this means the token names no version at all — distinct from naming
/// a stale one, and callers separate the two.
pub fn is_secret_version_shaped(token: &str) -> bool {
    let Some(digits) = token.strip_prefix('v') else {
        return false;
    };

    digits.len() == VERSION_DIGITS && digits.bytes().all(|byte| TOKEN_ALPHABET.contains(&byte))
}

/// Whether `token` is the one this server issues for `version`.
///
/// Renders the stored version and compares; no token is ever decoded back into
/// a number.
pub fn verify_secret_version(version: i64, token: &str) -> bool {
    is_secret_version_shaped(token) && secret_version(version) == token
}

/// Map a version onto its point in the permuted space.
///
/// Multiplying by an odd constant modulo `2^40` is a bijection on that space,
/// and adding a constant preserves that. [`secret_version`] rejects values
/// outside the supported space before calling this helper.
fn permute_version(version: i64) -> u64 {
    let mask = (1_u64 << VERSION_BITS) - 1;
    let seed = (version as u64) & mask;

    seed.wrapping_mul(VERSION_MULTIPLIER)
        .wrapping_add(VERSION_OFFSET)
        & mask
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    //----------------------------------------------------------------------------------------------
    // Rotation
    //----------------------------------------------------------------------------------------------

    #[test]
    fn a_token_is_a_v_and_eight_url_safe_characters() {
        for version in [0_i64, 1, 7, 42, 1_000_000] {
            let token = secret_version(version);

            assert_eq!(token.len(), 1 + VERSION_DIGITS);
            assert!(token.starts_with('v'));
            assert!(
                token[1..]
                    .bytes()
                    .all(|byte| TOKEN_ALPHABET.contains(&byte)),
                "{token} must use only the published alphabet"
            );
        }
    }

    /// Injectivity over the whole space rests on the multiplier being odd,
    /// which is what makes it invertible modulo a power of two. An even
    /// multiplier collides in a region no sampled range would reach.
    #[test]
    fn the_permutation_multiplier_is_invertible() {
        assert_eq!(VERSION_MULTIPLIER % 2, 1);
        assert!(VERSION_MULTIPLIER < (1 << VERSION_BITS));
    }

    /// Two versions sharing a token would let one caller's precondition satisfy
    /// another's write.
    #[test]
    fn distinct_versions_render_to_distinct_tokens() {
        let mut seen = HashSet::new();

        for version in 0_i64..200_000 {
            assert!(
                seen.insert(secret_version(version)),
                "version {version} collided with an earlier token"
            );
        }
    }

    /// A client that can see an ordering will compute one. Consecutive versions
    /// must therefore share no prefix a reader could extrapolate.
    #[test]
    fn consecutive_versions_render_to_dissimilar_tokens() {
        for version in 0_i64..5_000 {
            let current = secret_version(version);
            let next = secret_version(version + 1);

            let shared = current
                .bytes()
                .zip(next.bytes())
                .take_while(|(left, right)| left == right)
                .count();

            // The leading `v` is the only character every token shares.
            assert_eq!(
                shared, 1,
                "{current} and {next} share {shared} leading characters"
            );

            let differing = current
                .bytes()
                .zip(next.bytes())
                .filter(|(left, right)| left != right)
                .count();

            assert!(
                differing >= 4,
                "{current} and {next} differ in only {differing} characters"
            );
        }
    }

    #[test]
    fn verification_accepts_only_the_token_for_that_version() {
        for version in [1_i64, 7, 42, 1_000_000] {
            assert!(verify_secret_version(version, &secret_version(version)));

            // An adjacent version is the token a client guessing at an ordering
            // would most plausibly send.
            assert!(!verify_secret_version(
                version,
                &secret_version(version + 1)
            ));
            assert!(!verify_secret_version(
                version,
                &secret_version(version - 1)
            ));
        }
    }

    #[test]
    fn versions_outside_the_supported_domain_fail_closed() {
        for version in [-1_i64, 1_i64 << VERSION_BITS, i64::MAX] {
            let token = secret_version(version);
            assert_eq!(token, INVALID_VERSION_TOKEN);
            assert!(!is_secret_version_shaped(&token));
            assert!(!verify_secret_version(version, &token));
        }
    }

    #[test]
    fn a_malformed_or_foreign_token_never_verifies() {
        let version = 7_i64;
        let token = secret_version(version);

        for foreign in [
            String::new(),
            "v7".into(),
            "7".into(),
            token[1..].to_string(),
            token.to_uppercase(),
            format!("\"{token}\""),
            format!("{token}x"),
            token[..token.len() - 1].to_string(),
        ] {
            assert!(
                !verify_secret_version(version, &foreign),
                "{foreign:?} must not verify"
            );
        }
    }

    #[test]
    fn every_issued_token_is_shaped() {
        for version in [0_i64, 1, 7, 42, 1_000_000] {
            assert!(is_secret_version_shaped(&secret_version(version)));
        }
    }

    /// Shape is what separates "names no version" from "names a stale one".
    #[test]
    fn a_token_this_server_never_issues_is_unshaped() {
        let token = secret_version(7);

        for unshaped in [
            String::new(),
            "v7".into(),
            "7".into(),
            token[1..].to_string(),
            token.to_uppercase(),
            format!("\"{token}\""),
            format!("{token}x"),
            token[..token.len() - 1].to_string(),
            // `i`, `l`, `o` and `u` are excluded from the alphabet.
            "viiiiiiii".into(),
        ] {
            assert!(
                !is_secret_version_shaped(&unshaped),
                "{unshaped:?} must not be shaped"
            );
        }
    }

    //----------------------------------------------------------------------------------------------
    // Projection
    //----------------------------------------------------------------------------------------------

    /// The version token is the precondition for the next conditional
    /// rotation, so a projection that drops or rewrites it silently turns
    /// every following write unconditional.
    #[test]
    fn projecting_metadata_preserves_the_version_token() {
        let updated_at = Utc::now();
        let wire = CloudSecretMetadata {
            name: "API_KEY".to_string(),
            version: secret_version(7),
            updated_at,
        };

        let neutral = SecretMetadata::from(wire.clone());

        assert_eq!(neutral.name, "API_KEY");
        assert_eq!(neutral.version, wire.version);
        assert_eq!(neutral.updated_at, updated_at);
    }

    /// The disposition is the whole answer to "is this live yet?", so each
    /// wire variant must land on its own neutral variant rather than
    /// collapsing onto a default.
    #[test]
    fn projecting_a_result_preserves_the_version_and_disposition() {
        for (wire, expected) in [
            (CloudSecretDisposition::Applied, SecretDisposition::Applied),
            (
                CloudSecretDisposition::OnNextStart,
                SecretDisposition::OnNextStart,
            ),
            (
                CloudSecretDisposition::Unconfirmed,
                SecretDisposition::Unconfirmed,
            ),
        ] {
            let result = SecretRotationResult::from(CloudSecretRotationResult {
                name: "API_KEY".to_string(),
                version: secret_version(9),
                disposition: wire,
            });

            assert_eq!(result.name, "API_KEY");
            assert_eq!(result.version, secret_version(9));
            assert_eq!(result.disposition, expected);
        }
    }

    /// Renaming the Rust field to `disposition` must not move the JSON key.
    /// The operation envelope nests both enums, so this pins the whole shape:
    /// `status` from the operation, `application` from the result.
    #[test]
    fn the_rotation_wire_shape_survives_the_rust_rename() {
        let operation = CloudSecretRotationOperation {
            id: "op-1".to_string(),
            status: CloudSecretOperationStatus::Succeeded,
            result: Some(CloudSecretRotationResult {
                name: "API_KEY".to_string(),
                version: "v2".to_string(),
                disposition: CloudSecretDisposition::OnNextStart,
            }),
            error: None,
        };

        let json = serde_json::to_value(&operation).expect("operation serializes");
        assert_eq!(json["status"], "succeeded");
        assert_eq!(json["result"]["application"], "on_next_start");
        assert!(json["result"].get("disposition").is_none());

        // And the same bytes a shipped client already sends still parse.
        let parsed: CloudSecretRotationOperation = serde_json::from_str(
            r#"{"id":"op-1","status":"succeeded","result":{"name":"API_KEY","version":"v2","application":"on_next_start"}}"#,
        )
        .expect("shipped wire shape parses");
        let result = parsed.result.expect("succeeded carries a result");
        assert_eq!(result.disposition, CloudSecretDisposition::OnNextStart);
    }

    /// A neutral request reaches the server through the wire twin, so the
    /// precondition the caller supplied has to survive that hop.
    #[test]
    fn projecting_a_request_onto_the_wire_keeps_the_precondition() {
        let wire = CloudSecretRotationRequest::from(SecretRotationRequest {
            value: "new-material".to_string(),
            version: Some(secret_version(3)),
        });

        assert_eq!(wire.value, "new-material");
        assert_eq!(wire.version, Some(secret_version(3)));
    }

    /// Secret material must never reach a log, on either side of the boundary.
    /// Both `Debug` impls are hand-written, so both need holding down.
    #[test]
    fn debug_redacts_the_value_on_both_sides_of_the_boundary() {
        const MATERIAL: &str = "sk-live-do-not-log-me";

        let neutral = SecretRotationRequest {
            value: MATERIAL.to_string(),
            version: Some(secret_version(1)),
        };
        let wire = CloudSecretRotationRequest::from(neutral.clone());

        for rendered in [format!("{neutral:?}"), format!("{wire:?}")] {
            assert!(!rendered.contains(MATERIAL), "value leaked: {rendered}");
            assert!(rendered.contains("[REDACTED]"), "{rendered}");
            assert!(rendered.contains(&secret_version(1)), "{rendered}");
        }
    }
}

//! Backend-neutral secret rotation contracts.
//!
//! A backend with its own wire shape projects onto these at its boundary, so
//! the SDK surface names one type per concept whoever serves it.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One secret's metadata, as a backend publishes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct SecretMetadata {
    /// The configured env var name, and the only identifier this exposes.
    pub name: String,
    /// Opaque: no ordering, nothing to decode, equality only. Quote it back on
    /// the next conditional rotation.
    pub version: String,
    /// The backend's own timestamp, never a local clock.
    #[cfg_attr(feature = "ts", ts(type = "string"))]
    pub updated_at: DateTime<Utc>,
}

/// A request to replace one secret's material.
///
/// `Debug` is hand-written: the derive would print the value.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct SecretRotationRequest {
    /// New plaintext, at most 64 KiB of UTF-8 and never empty.
    pub value: String,
    /// Absent means no precondition; what that licenses is the backend's call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// How far a committed version got toward the running runtime.
///
/// Named for [`ModificationDisposition`], which answers the same question one
/// layer down - *when or whether a planned change can take effect*. This is
/// the rotation-shaped answer to it, and is deliberately distinct from the
/// status of the operation that carried the rotation.
///
/// [`ModificationDisposition`]: crate::ModificationDisposition
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum SecretDisposition {
    /// The authoritative runtime acknowledged it. Nothing to do.
    Applied,
    /// Durable, but not delivered live. A future start reads it.
    OnNextStart,
    /// Durable, but the current runtime could not be confirmed. Reassert the
    /// value or restart if immediate convergence matters.
    Unconfirmed,
}

/// The settled outcome of a rotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct SecretRotationResult {
    /// The configured env var name this result reports on.
    pub name: String,
    /// The committed version, usable as the next precondition without a
    /// further metadata read.
    pub version: String,
    /// How far the new value reached: stored, or confirmed live.
    ///
    /// The wire key stays `application`: this shape has shipped, so only the
    /// Rust-side name changed.
    #[serde(rename = "application")]
    pub disposition: SecretDisposition,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl std::fmt::Debug for SecretRotationRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretRotationRequest")
            .field("value", &"[REDACTED]")
            .field("version", &self.version)
            .finish()
    }
}

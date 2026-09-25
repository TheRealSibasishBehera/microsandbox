//! Backend-neutral sandbox secret rotation dispatch.

use std::sync::Arc;

use futures::future::BoxFuture;
use microsandbox_types::{SecretMetadata, SecretRotationRequest, SecretRotationResult};

use super::Backend;
use crate::MicrosandboxResult;

/// Backend implementation for per-sandbox secret operations.
pub trait SecretBackend: Send + Sync {
    /// Each entry carries the token a conditional rotation must quote.
    fn list<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        sandbox: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<SecretMetadata>>>;

    /// Rotate one secret, returning a settled outcome rather than a job to
    /// poll: an asynchronous transport resolves that internally.
    fn rotate<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        sandbox: &'a str,
        name: &'a str,
        request: SecretRotationRequest,
    ) -> BoxFuture<'a, MicrosandboxResult<SecretRotationResult>>;
}

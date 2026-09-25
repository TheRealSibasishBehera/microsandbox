//! Local sandbox secret operations.

use std::sync::Arc;

use futures::future::BoxFuture;
use microsandbox_types::{SecretMetadata, SecretRotationRequest, SecretRotationResult};

use super::LocalBackend;
use crate::MicrosandboxResult;
use crate::backend::{Backend, SecretBackend};

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl SecretBackend for LocalBackend {
    /// No versioned store locally, so there is no token to publish. Refusing
    /// beats an empty list, which would read as "this sandbox holds none".
    fn list<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _sandbox: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<SecretMetadata>>> {
        Box::pin(async move {
            Err(crate::MicrosandboxError::unsupported(
                crate::error::Operation::SecretList,
                crate::error::UnsupportedReason::CloudOnly,
            ))
        })
    }

    /// Local rotation goes through `Sandbox::modify`, as one batched
    /// control-socket update. Nothing here commits a version to report.
    fn rotate<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _sandbox: &'a str,
        _name: &'a str,
        _request: SecretRotationRequest,
    ) -> BoxFuture<'a, MicrosandboxResult<SecretRotationResult>> {
        Box::pin(async move {
            Err(crate::MicrosandboxError::unsupported(
                crate::error::Operation::SecretRotate,
                crate::error::UnsupportedReason::CloudOnly,
            ))
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MicrosandboxError;
    use crate::backend::LocalBackend;

    async fn local_backend() -> Arc<dyn Backend> {
        let home = tempfile::tempdir().unwrap();
        Arc::new(
            LocalBackend::builder()
                .home(home.path())
                .build()
                .await
                .unwrap(),
        )
    }

    #[tokio::test]
    async fn local_secret_list_fails_closed() {
        let backend = local_backend().await;

        let error = backend
            .secrets()
            .list(backend.clone(), "api")
            .await
            .expect_err("Local must never report a secret listing it cannot derive");
        assert!(matches!(
            error,
            MicrosandboxError::Unsupported {
                op: crate::error::Operation::SecretList,
                reason: crate::error::UnsupportedReason::CloudOnly,
            }
        ));
    }

    #[tokio::test]
    async fn local_secret_rotation_fails_closed() {
        let backend = local_backend().await;

        let error = backend
            .secrets()
            .rotate(
                backend.clone(),
                "api",
                "API_KEY",
                SecretRotationRequest {
                    value: "new-material".into(),
                    version: None,
                },
            )
            .await
            .expect_err("Local must never report a version it does not commit");
        assert!(matches!(
            error,
            MicrosandboxError::Unsupported {
                op: crate::error::Operation::SecretRotate,
                reason: crate::error::UnsupportedReason::CloudOnly,
            }
        ));
    }
}

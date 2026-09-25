//! Per-sandbox secret listing and rotation.
//!
//! A sandbox's secrets are named environment values the runtime injects. This
//! module is the user-facing entry point onto
//! [`SecretBackend`](crate::backend::SecretBackend): [`Secret::list`] reads the
//! published metadata, and [`Secret::rotate`] replaces one secret's material
//! and reports the settled outcome.
//!
//! Like [`Volume`](crate::volume::Volume) and
//! [`Snapshot`](crate::snapshot::Snapshot), the entry points are associated
//! functions that resolve the ambient
//! [`default_backend`](crate::backend::default_backend) and delegate. Cloud is
//! the backend that serves them; local fails closed with
//! [`MicrosandboxError::Unsupported`](crate::MicrosandboxError::Unsupported)
//! rather than reporting a version it does not commit.
//!
//! Secret material is only ever an input. Nothing in this module returns,
//! logs, or formats a plaintext value — [`SecretRotationRequest`]'s `Debug`
//! redacts it, and the types that come back
//! ([`SecretMetadata`], [`SecretRotationResult`]) carry names and opaque
//! version tokens only.

pub use microsandbox_types::{
    SecretDisposition, SecretMetadata, SecretRotationRequest, SecretRotationResult,
};

use crate::MicrosandboxResult;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Entry point for a sandbox's secrets.
///
/// A namespace rather than a value: secrets are addressed by sandbox and name,
/// and hold no client-side state worth carrying between calls.
pub struct Secret;

/// Builder for a single secret rotation, constructed via [`Secret::rotate`].
///
/// A rotation is a value plus an optional version precondition, so the builder
/// keeps the required part positional and the precondition a named step:
///
/// ```ignore
/// // Rotate whatever is current.
/// Secret::rotate("api", "API_KEY", "new-material").send().await?;
///
/// // Rotate only if the secret is still at the version we read.
/// Secret::rotate("api", "API_KEY", "new-material")
///     .if_version(&metadata.version)
///     .send()
///     .await?;
/// ```
///
/// `Debug` is hand-written: the derive would print the new value.
pub struct SecretRotationBuilder {
    sandbox: String,
    name: String,
    request: SecretRotationRequest,
}

//--------------------------------------------------------------------------------------------------
// Methods: Secret
//--------------------------------------------------------------------------------------------------

impl Secret {
    /// List a sandbox's secrets from the active backend.
    ///
    /// Each entry carries the opaque version token a conditional rotation must
    /// quote. Values are never returned; metadata only.
    ///
    /// The local backend returns
    /// [`MicrosandboxError::Unsupported`](crate::MicrosandboxError::Unsupported)
    /// because it keeps no versioned store — refusing beats an empty list,
    /// which would read as "this sandbox holds none".
    pub async fn list(sandbox: &str) -> MicrosandboxResult<Vec<SecretMetadata>> {
        let backend = crate::backend::default_backend();
        backend.secrets().list(backend.clone(), sandbox).await
    }

    /// Start a rotation of one secret on the active backend.
    ///
    /// Call [`send`](SecretRotationBuilder::send) to apply it, optionally
    /// after [`if_version`](SecretRotationBuilder::if_version) to make the
    /// write conditional on the version last read.
    pub fn rotate(
        sandbox: impl Into<String>,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> SecretRotationBuilder {
        SecretRotationBuilder::new(sandbox, name, value)
    }

    /// Rotate one secret from a pre-built [`SecretRotationRequest`].
    ///
    /// The escape hatch for callers holding a request they built or
    /// deserialized themselves; [`Secret::rotate`] is the ergonomic path.
    ///
    /// Returns the settled outcome — the committed version plus how far it
    /// reached — rather than a job to poll. An asynchronous transport resolves
    /// that internally.
    pub async fn rotate_with(
        sandbox: &str,
        name: &str,
        request: SecretRotationRequest,
    ) -> MicrosandboxResult<SecretRotationResult> {
        let backend = crate::backend::default_backend();
        backend
            .secrets()
            .rotate(backend.clone(), sandbox, name, request)
            .await
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: SecretRotationBuilder
//--------------------------------------------------------------------------------------------------

impl SecretRotationBuilder {
    /// Start building a rotation of `name` on `sandbox` to `value`.
    pub fn new(
        sandbox: impl Into<String>,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Self {
            sandbox: sandbox.into(),
            name: name.into(),
            request: SecretRotationRequest {
                value: value.into(),
                version: None,
            },
        }
    }

    /// Apply only if the secret is still at `version`, as read from a
    /// [`SecretMetadata`] or an earlier [`SecretRotationResult`].
    ///
    /// Omit it to rotate whatever is current. The authoritative backend
    /// resolves the live token while serializing the write.
    pub fn if_version(mut self, version: impl Into<String>) -> Self {
        self.request.version = Some(version.into());
        self
    }

    /// Build the request without sending it.
    pub fn build(self) -> SecretRotationRequest {
        self.request
    }

    /// Apply the rotation through the ambient
    /// [`default_backend`](crate::backend::default_backend).
    pub async fn send(self) -> MicrosandboxResult<SecretRotationResult> {
        Secret::rotate_with(&self.sandbox, &self.name, self.request).await
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl std::fmt::Debug for SecretRotationBuilder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretRotationBuilder")
            .field("sandbox", &self.sandbox)
            .field("name", &self.name)
            .field("request", &self.request)
            .finish()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, feature = "cloud", feature = "local"))]
mod tests {
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::backend::{Backend, CloudBackend, LocalBackend};
    use crate::{MicrosandboxError, error::Operation, error::UnsupportedReason};

    async fn serve(bodies: Vec<&'static str>) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("address"));
        let server = tokio::spawn(async move {
            let mut requests = Vec::new();
            for body in bodies {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let mut buffer = [0u8; 2048];
                let read = stream.read(&mut buffer).await.expect("read request");
                requests.push(String::from_utf8_lossy(&buffer[..read]).to_string());
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write response");
                stream.shutdown().await.expect("shutdown");
            }
            requests
        });
        (url, server)
    }

    fn target(request: &str) -> String {
        request
            .lines()
            .next()
            .unwrap_or_default()
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ")
    }

    const SANDBOX: &str = r#"{"id":"sandbox-id","org_id":"org-id","name":"api","slug":"api","status":"running","ephemeral":false,"created_at":"2026-01-01T00:00:00Z"}"#;

    async fn cloud(url: &str) -> Arc<dyn Backend> {
        Arc::new(CloudBackend::new(url, "msb_test_key").expect("cloud backend"))
    }

    async fn local() -> Arc<dyn Backend> {
        let home = tempfile::tempdir().expect("tempdir");
        Arc::new(
            LocalBackend::builder()
                .home(home.path())
                .build()
                .await
                .expect("local backend"),
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn list_routes_through_the_ambient_backend() {
        let (url, server) = serve(vec![
            SANDBOX,
            r#"{"data":[{"name":"API_KEY","version":"v1","updated_at":"2026-01-01T00:00:00Z"}]}"#,
        ])
        .await;
        let backend = cloud(&url).await;

        let secrets = crate::backend::with_backend(backend, Secret::list("api"))
            .await
            .expect("listing succeeds");

        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].name, "API_KEY");
        assert_eq!(secrets[0].version, "v1");
        let requests = server.await.expect("join server");
        assert_eq!(target(&requests[1]), "GET /v1/sandboxes/sandbox-id/secrets");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rotate_with_a_version_sends_it_as_the_precondition() {
        let (url, server) = serve(vec![
            SANDBOX,
            r#"{"id":"op-1","status":"succeeded","result":{"name":"API_KEY","version":"v2","application":"applied"}}"#,
        ])
        .await;
        let backend = cloud(&url).await;

        let result = crate::backend::with_backend(
            backend,
            Secret::rotate("api", "API_KEY", "new-material")
                .if_version("v1")
                .send(),
        )
        .await
        .expect("rotation settles");

        assert_eq!(result.version, "v2");
        assert_eq!(result.disposition, SecretDisposition::Applied);
        let requests = server.await.expect("join server");
        assert_eq!(
            target(&requests[1]),
            "PUT /v1/sandboxes/sandbox-id/secrets/API_KEY"
        );
        assert!(requests[1].contains(r#""version":"v1""#), "{}", requests[1]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rotate_without_a_version_resolves_the_current_precondition() {
        let (url, server) = serve(vec![
            SANDBOX,
            r#"{"data":[{"name":"API_KEY","version":"v9current","updated_at":"2026-01-01T00:00:00Z"}]}"#,
            r#"{"id":"op-2","status":"succeeded","result":{"name":"API_KEY","version":"v10","application":"applied"}}"#,
        ])
        .await;
        let backend = cloud(&url).await;

        let result = crate::backend::with_backend(
            backend,
            Secret::rotate("api", "API_KEY", "new-material").send(),
        )
        .await
        .expect("rotation settles");

        assert_eq!(result.version, "v10");
        let requests = server.await.expect("join server");
        assert_eq!(requests.len(), 3);
        assert_eq!(target(&requests[1]), "GET /v1/sandboxes/sandbox-id/secrets");
        assert_eq!(
            target(&requests[2]),
            "PUT /v1/sandboxes/sandbox-id/secrets/API_KEY"
        );
        assert!(
            requests[2].contains(r#""version":"v9current""#),
            "{}",
            requests[2]
        );
    }

    #[test]
    fn the_builder_builds_and_redacts_its_request() {
        let request = Secret::rotate("api", "API_KEY", "new-material")
            .if_version("v1")
            .build();
        assert_eq!(request.value, "new-material");
        assert_eq!(request.version.as_deref(), Some("v1"));

        let rendered = format!(
            "{:?}",
            Secret::rotate("api", "API_KEY", "super-secret-material").if_version("v1")
        );
        assert!(!rendered.contains("super-secret-material"), "{rendered}");
        assert!(rendered.contains("[REDACTED]"), "{rendered}");
    }

    #[tokio::test]
    async fn local_operations_fail_closed() {
        let backend = local().await;
        let list_error = crate::backend::with_backend(backend.clone(), Secret::list("api"))
            .await
            .expect_err("local has no versioned store to list");
        assert!(matches!(
            list_error,
            MicrosandboxError::Unsupported {
                op: Operation::SecretList,
                reason: UnsupportedReason::CloudOnly,
            }
        ));

        let rotate_error = crate::backend::with_backend(
            backend,
            Secret::rotate("api", "API_KEY", "new-material").send(),
        )
        .await
        .expect_err("local commits no version to report");
        assert!(matches!(
            rotate_error,
            MicrosandboxError::Unsupported {
                op: Operation::SecretRotate,
                reason: UnsupportedReason::CloudOnly,
            }
        ));
    }

    #[test]
    fn operation_names_match_the_secret_api() {
        assert_eq!(Operation::SecretList.api_path(), "Secret::list");
        assert_eq!(Operation::SecretRotate.api_path(), "Secret::rotate");
    }
}

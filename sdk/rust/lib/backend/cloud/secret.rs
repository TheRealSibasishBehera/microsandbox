//! Cloud sandbox secret listing and rotation.

use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::future::BoxFuture;
use microsandbox_types::{
    CloudSecretMetadataList, CloudSecretOperationStatus, CloudSecretRotationOperation,
    CloudSecretRotationRequest, CloudSecretRotationResult, SecretMetadata, SecretRotationRequest,
    SecretRotationResult,
};

use super::CloudBackend;
use super::http::{cloud_io_error, decode_json, urlencoding};
use crate::backend::{Backend, SecretBackend};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const SECRET_ROTATION_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const SECRET_ROTATION_INITIAL_POLL_INTERVAL: Duration = Duration::from_millis(250);
const SECRET_ROTATION_MAX_POLL_INTERVAL: Duration = Duration::from_secs(5);

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl SecretBackend for CloudBackend {
    fn list<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        sandbox: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<SecretMetadata>>> {
        Box::pin(async move {
            let id = self.get_sandbox(sandbox).await?.id;
            let listing = self.list_secrets(&id).await?;
            Ok(listing.data.into_iter().map(Into::into).collect())
        })
    }

    fn rotate<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        sandbox: &'a str,
        name: &'a str,
        request: SecretRotationRequest,
    ) -> BoxFuture<'a, MicrosandboxResult<SecretRotationResult>> {
        Box::pin(async move {
            let id = self.get_sandbox(sandbox).await?.id;
            let request = CloudSecretRotationRequest::from(request);

            // The public Secret API treats a missing precondition as "whatever is
            // current", while the Cloud API deliberately requires an explicit
            // token on every write. Resolve that token here. A concurrent write
            // after this read still loses safely at the server-side compare.
            let request = match request.version {
                Some(_) => request,
                None => CloudSecretRotationRequest {
                    version: Some(self.current_secret_version(&id, name).await?),
                    ..request
                },
            };

            let operation = self.rotate_secret(&id, name, &request).await?;
            Ok(self.wait_for_secret_rotation(operation).await?.into())
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CloudBackend {
    /// Resolve the current opaque version for an unconditional client call.
    async fn current_secret_version(
        &self,
        sandbox_id: &str,
        name: &str,
    ) -> MicrosandboxResult<String> {
        self.list_secrets(sandbox_id)
            .await?
            .data
            .into_iter()
            .find(|secret| secret.name == name)
            .map(|secret| secret.version)
            .ok_or_else(|| {
                MicrosandboxError::Runtime(format!("sandbox {sandbox_id:?} has no secret {name:?}"))
            })
    }

    async fn list_secrets(&self, sandbox_id: &str) -> MicrosandboxResult<CloudSecretMetadataList> {
        let url = format!(
            "{}/v1/sandboxes/{}/secrets",
            self.url,
            urlencoding(sandbox_id)
        );
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|error| cloud_io_error("GET /v1/sandboxes/:id/secrets", error))?;
        decode_json(response, "GET /v1/sandboxes/:id/secrets").await
    }

    /// The precondition rides in the body's `version` field; the route defines
    /// no conditional request header.
    async fn rotate_secret(
        &self,
        sandbox_id: &str,
        name: &str,
        request: &CloudSecretRotationRequest,
    ) -> MicrosandboxResult<CloudSecretRotationOperation> {
        let url = format!(
            "{}/v1/sandboxes/{}/secrets/{}",
            self.url,
            urlencoding(sandbox_id),
            urlencoding(name)
        );
        let response = self
            .http
            .put(&url)
            .json(request)
            .send()
            .await
            .map_err(|error| cloud_io_error("PUT /v1/sandboxes/:id/secrets/:name", error))?;
        decode_json(response, "PUT /v1/sandboxes/:id/secrets/:name").await
    }

    async fn get_secret_rotation_operation(
        &self,
        id: &str,
    ) -> MicrosandboxResult<CloudSecretRotationOperation> {
        let url = format!(
            "{}/v1/secret-rotation-operations/{}",
            self.url,
            urlencoding(id)
        );
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|error| cloud_io_error("GET /v1/secret-rotation-operations/:id", error))?;
        decode_json(response, "GET /v1/secret-rotation-operations/:id").await
    }

    /// Drive an accepted rotation to its settled outcome.
    ///
    /// The route answers 202 with `in_progress` whenever delivery outlives the
    /// request, so acceptance alone says nothing about the committed version.
    async fn wait_for_secret_rotation(
        &self,
        mut operation: CloudSecretRotationOperation,
    ) -> MicrosandboxResult<CloudSecretRotationResult> {
        let started = Instant::now();
        let mut poll_interval = SECRET_ROTATION_INITIAL_POLL_INTERVAL;
        loop {
            match operation.status {
                CloudSecretOperationStatus::Succeeded => {
                    return operation.result.ok_or_else(|| {
                        MicrosandboxError::Runtime(format!(
                            "secret rotation operation {} succeeded without a result",
                            operation.id
                        ))
                    });
                }
                CloudSecretOperationStatus::Failed => {
                    let detail = operation
                        .error
                        .map(|error| format!("{}: {}", error.code, error.message));
                    return Err(MicrosandboxError::Runtime(format!(
                        "secret rotation operation {} failed{}",
                        operation.id,
                        detail
                            .map(|detail| format!(": {detail}"))
                            .unwrap_or_default()
                    )));
                }
                CloudSecretOperationStatus::InProgress => {}
            }

            if started.elapsed() >= SECRET_ROTATION_TIMEOUT {
                return Err(MicrosandboxError::Runtime(format!(
                    "secret rotation operation {} did not finish within {:?}; server-side work may still be continuing",
                    operation.id, SECRET_ROTATION_TIMEOUT,
                )));
            }

            tokio::time::sleep(poll_interval).await;
            operation = self.get_secret_rotation_operation(&operation.id).await?;
            poll_interval = poll_interval
                .saturating_mul(2)
                .min(SECRET_ROTATION_MAX_POLL_INTERVAL);
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use microsandbox_types::SecretDisposition;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    /// Serve one canned JSON body per connection, in order, and report the
    /// requests that were made, headers and body included.
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

    /// The method and path of a recorded request, without its headers or body.
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

    fn request() -> SecretRotationRequest {
        SecretRotationRequest {
            value: "new-material".into(),
            version: Some("v1".into()),
        }
    }

    const SANDBOX: &str = r#"{"id":"sandbox-id","org_id":"org-id","name":"api","slug":"api","status":"running","ephemeral":false,"created_at":"2026-01-01T00:00:00Z"}"#;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rotate_polls_until_the_operation_settles() {
        let (url, server) = serve(vec![
            SANDBOX,
            r#"{"id":"op-1","status":"in_progress"}"#,
            r#"{"id":"op-1","status":"in_progress"}"#,
            r#"{"id":"op-1","status":"succeeded","result":{"name":"API_KEY","version":"v2","application":"applied"}}"#,
        ])
        .await;
        let backend: Arc<dyn Backend> =
            Arc::new(CloudBackend::new(&url, "msb_test_key").expect("cloud backend"));

        let result = backend
            .secrets()
            .rotate(backend.clone(), "api", "API_KEY", request())
            .await
            .expect("rotation settles");

        assert_eq!(result.version, "v2");
        assert_eq!(result.disposition, SecretDisposition::Applied);
        let requests = server.await.expect("join server");
        assert_eq!(
            target(&requests[1]),
            "PUT /v1/sandboxes/sandbox-id/secrets/API_KEY"
        );
        assert_eq!(
            target(&requests[2]),
            "GET /v1/secret-rotation-operations/op-1"
        );
        assert_eq!(
            target(&requests[3]),
            "GET /v1/secret-rotation-operations/op-1"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_rotation_surfaces_its_error_code() {
        let (url, server) = serve(vec![
            SANDBOX,
            r#"{"id":"op-2","status":"failed","error":{"code":"version_conflict","message":"the secret changed"}}"#,
        ])
        .await;
        let backend: Arc<dyn Backend> =
            Arc::new(CloudBackend::new(&url, "msb_test_key").expect("cloud backend"));

        let error = backend
            .secrets()
            .rotate(backend.clone(), "api", "API_KEY", request())
            .await
            .expect_err("failed rotation is an error");

        let message = error.to_string();
        assert!(message.contains("version_conflict"), "{message}");
        assert!(message.contains("the secret changed"), "{message}");
        server.await.expect("join server");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn list_returns_the_published_metadata() {
        let (url, server) = serve(vec![
            SANDBOX,
            r#"{"data":[{"name":"API_KEY","version":"v1","updated_at":"2026-01-01T00:00:00Z"}]}"#,
        ])
        .await;
        let backend: Arc<dyn Backend> =
            Arc::new(CloudBackend::new(&url, "msb_test_key").expect("cloud backend"));

        let secrets = backend
            .secrets()
            .list(backend.clone(), "api")
            .await
            .expect("listing succeeds");

        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].name, "API_KEY");
        assert_eq!(secrets[0].version, "v1");
        let requests = server.await.expect("join server");
        assert_eq!(target(&requests[1]), "GET /v1/sandboxes/sandbox-id/secrets");
    }

    /// The server requires a version on every rotation. A caller that names
    /// none is asserting "whatever is current", so the backend reads and
    /// quotes the current token rather than sending an invalid request.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_absent_version_resolves_to_the_current_one() {
        let (url, server) = serve(vec![
            SANDBOX,
            r#"{"data":[{"name":"API_KEY","version":"v9current","updated_at":"2026-01-01T00:00:00Z"}]}"#,
            r#"{"id":"op-3","status":"succeeded","result":{"name":"API_KEY","version":"v10","application":"applied"}}"#,
        ])
        .await;
        let backend: Arc<dyn Backend> =
            Arc::new(CloudBackend::new(&url, "msb_test_key").expect("cloud backend"));

        let result = backend
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
            .expect("rotation settles");

        assert_eq!(result.version, "v10");
        let requests = server.await.expect("join server");
        assert_eq!(target(&requests[1]), "GET /v1/sandboxes/sandbox-id/secrets");
        assert_eq!(
            target(&requests[2]),
            "PUT /v1/sandboxes/sandbox-id/secrets/API_KEY"
        );
        assert!(
            requests[2].contains(r#""version":"v9current""#),
            "the rotation must quote the version it read: {}",
            requests[2]
        );
    }

    /// Resolution is a fallback, not a step. A caller holding a token gets that
    /// token sent, with no extra read that could widen the conflict window.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_named_version_is_sent_without_re_reading_it() {
        let (url, server) = serve(vec![
            SANDBOX,
            r#"{"id":"op-4","status":"succeeded","result":{"name":"API_KEY","version":"v2","application":"applied"}}"#,
        ])
        .await;
        let backend: Arc<dyn Backend> =
            Arc::new(CloudBackend::new(&url, "msb_test_key").expect("cloud backend"));

        backend
            .secrets()
            .rotate(backend.clone(), "api", "API_KEY", request())
            .await
            .expect("rotation settles");

        let requests = server.await.expect("join server");
        assert_eq!(
            target(&requests[1]),
            "PUT /v1/sandboxes/sandbox-id/secrets/API_KEY"
        );
        assert!(requests[1].contains(r#""version":"v1""#), "{}", requests[1]);
    }

    /// Resolution cannot invent a precondition for a secret that is not there.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_absent_version_for_an_unknown_secret_is_an_error() {
        let (url, server) = serve(vec![SANDBOX, r#"{"data":[]}"#]).await;
        let backend: Arc<dyn Backend> =
            Arc::new(CloudBackend::new(&url, "msb_test_key").expect("cloud backend"));

        let error = backend
            .secrets()
            .rotate(
                backend.clone(),
                "api",
                "MISSING",
                SecretRotationRequest {
                    value: "new-material".into(),
                    version: None,
                },
            )
            .await
            .expect_err("an unknown secret has no version to quote");

        assert!(error.to_string().contains("has no secret"));
        let requests = server.await.expect("join server");
        assert_eq!(target(&requests[1]), "GET /v1/sandboxes/sandbox-id/secrets");
        assert_eq!(requests.len(), 2, "rotation must not be attempted");
    }
}

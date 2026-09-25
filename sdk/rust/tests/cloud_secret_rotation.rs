//! Live smoke test for the Cloud secret client API.
//!
//! This test is ignored by default because it mutates one named secret in a
//! real Cloud sandbox. Run it through
//! `scripts/smoke/cloud/secret-rotation.sh`, which validates the required
//! environment and records the source identity first.

use std::env;
use std::sync::Arc;
use std::time::Duration;

use microsandbox::{
    Backend, CloudBackend, MicrosandboxError, Secret, SecretDisposition, SecretMetadata,
    with_backend,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const METADATA_CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(15);
const METADATA_POLL_INTERVAL: Duration = Duration::from_millis(250);

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

/// Exercise the public client API against a real msb-cloud API.
///
/// The test intentionally uses only `Secret::list` and `Secret::rotate`; using
/// raw HTTP here would bypass the client API whose contract this smoke test exists
/// to validate. Secret material is read from the environment and is never
/// printed or included in assertion messages.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "mutates a real Cloud sandbox; use scripts/smoke/cloud/secret-rotation.sh"]
async fn cloud_secret_rotation_api_smoke() {
    let api_url = required("MSB_SECRET_TEST_API_URL");
    let api_key = required("MSB_SECRET_TEST_API_KEY");
    let sandbox = required("MSB_SECRET_TEST_SANDBOX");
    let name = required("MSB_SECRET_TEST_NAME");
    let value = required("MSB_SECRET_TEST_VALUE");

    let backend: Arc<dyn Backend> =
        Arc::new(CloudBackend::new(api_url, api_key).expect("construct Cloud backend"));

    let before = find_secret(backend.clone(), &sandbox, &name).await;
    let result = with_backend(
        backend.clone(),
        Secret::rotate(&sandbox, &name, value.clone())
            .if_version(&before.version)
            .send(),
    )
    .await
    .expect("conditional secret rotation must settle successfully");

    assert_eq!(
        result.disposition,
        SecretDisposition::Applied,
        "a running single-node sandbox must report an applied rotation"
    );
    assert_ne!(
        result.version, before.version,
        "a committed rotation must publish a new opaque version"
    );

    let deadline = tokio::time::Instant::now() + METADATA_CONVERGENCE_TIMEOUT;
    loop {
        let after = find_secret(backend.clone(), &sandbox, &name).await;
        if after.version == result.version {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "secret metadata did not converge to the settled rotation version"
        );
        tokio::time::sleep(METADATA_POLL_INTERVAL).await;
    }

    let stale = with_backend(
        backend.clone(),
        Secret::rotate(&sandbox, &name, value.clone())
            .if_version(&before.version)
            .send(),
    )
    .await;
    match stale {
        Err(MicrosandboxError::CloudHttp {
            status: 409,
            code: Some(code),
            ..
        }) if code == "secret_version_conflict" => {}
        Err(error) => panic!("stale rotation returned the wrong error: {error}"),
        Ok(_) => panic!("the pre-rotation version was accepted after the first write committed"),
    }

    // Exercise the ergonomic path too. The Cloud API requires a token, so the
    // Cloud backend must resolve and quote the current version internally.
    let unconditional = with_backend(
        backend.clone(),
        Secret::rotate(&sandbox, &name, value).send(),
    )
    .await
    .expect("unconditional rotation must resolve the current version");
    assert_eq!(unconditional.disposition, SecretDisposition::Applied);
    assert_ne!(
        unconditional.version, result.version,
        "the unconditional rotation must commit a new version"
    );

    let deadline = tokio::time::Instant::now() + METADATA_CONVERGENCE_TIMEOUT;
    loop {
        let after = find_secret(backend.clone(), &sandbox, &name).await;
        if after.version == unconditional.version {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "secret metadata did not converge after the unconditional rotation"
        );
        tokio::time::sleep(METADATA_POLL_INTERVAL).await;
    }

    println!(
        "Cloud SDK rotation passed: sandbox={sandbox} name={name} conditional={:?} unconditional={:?}",
        result.disposition, unconditional.disposition
    );
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn required(name: &str) -> String {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| panic!("required environment variable is missing: {name}"))
}

async fn find_secret(backend: Arc<dyn Backend>, sandbox: &str, name: &str) -> SecretMetadata {
    with_backend(backend, Secret::list(sandbox))
        .await
        .expect("list sandbox secret metadata")
        .into_iter()
        .find(|secret| secret.name == name)
        .unwrap_or_else(|| panic!("named secret is not published for the test sandbox: {name}"))
}

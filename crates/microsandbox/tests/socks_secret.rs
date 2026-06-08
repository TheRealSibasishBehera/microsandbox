//! Integration tests for secret substitution through SOCKS proxy tunnels.
//!
//! Each test boots a real sandbox and two in-process fixtures:
//!
//! - `HostHttps` — minimal TLS server on an ephemeral loopback port. The guest
//!   reaches it via `host.microsandbox.internal:{port}`, which the gateway
//!   rewrites to loopback.
//!
//! - `HostSocks` — minimal SOCKS5 proxy on a second ephemeral loopback port,
//!   also reachable as `host.microsandbox.internal:{socks_port}`. It accepts
//!   the SOCKS handshake and pipes the inner stream straight to `HostHttps`
//!   without doing any TLS itself. Microsandbox intercepts transparently.
//!
//! Run with:
//!     cargo nextest run -p microsandbox --tests --run-ignored=only

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use fast_socks5::server::{DnsResolveHelper, Socks5ServerProtocol, run_tcp_proxy};
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{Result as SocksResult, Socks5Command};
use microsandbox::{NetworkPolicy, Sandbox};
use rcgen::CertificateParams;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use test_utils::msb_test;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const CURL_IMAGE: &str = "mirror.gcr.io/curlimages/curl";
const REAL_SECRET: &str = "real-secret";
const HOST_ALIAS: &str = "host.microsandbox.internal";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Minimal in-process TLS server on loopback.
struct HostHttps {
    port: u16,
    handle: Option<JoinHandle<io::Result<Vec<u8>>>>,
}

/// Minimal in-process SOCKS5 proxy on loopback that pipes through to a target port.
struct HostSocks {
    port: u16,
    handle: Option<JoinHandle<()>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl HostHttps {
    async fn start() -> io::Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let v4 = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let port = v4.local_addr()?.port();
        let v6 = TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, port))).await?;
        let acceptor = TlsAcceptor::from(test_server_config());

        let handle = tokio::spawn(async move {
            let (stream, _) = tokio::select! {
                a = v4.accept() => a?,
                a = v6.accept() => a?,
            };
            let tls = acceptor.accept(stream).await?;
            receive_https_request(tls).await
        });

        Ok(Self {
            port,
            handle: Some(handle),
        })
    }

    fn port(&self) -> u16 {
        self.port
    }

    async fn received_headers(&mut self) -> io::Result<Vec<u8>> {
        self.handle
            .take()
            .expect("fixture already consumed")
            .await
            .map_err(io::Error::other)?
    }
}

impl Drop for HostHttps {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

impl HostSocks {
    /// Start a SOCKS5 proxy that forwards all CONNECT tunnels to `target_port`
    /// on loopback (where `HostHttps` is listening).
    async fn start(target_port: u16) -> io::Result<Self> {
        let v4 = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let port = v4.local_addr()?.port();
        let v6 = TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, port))).await?;

        let handle = tokio::spawn(async move {
            // Accept one connection (one test, one curl invocation).
            let (stream, _) = tokio::select! {
                a = v4.accept() => a.expect("socks v4 accept"),
                a = v6.accept() => a.expect("socks v6 accept"),
            };
            if let Err(e) = serve_socks5(stream, target_port).await {
                eprintln!("HostSocks error: {e}");
            }
        });

        Ok(Self {
            port,
            handle: Some(handle),
        })
    }

    fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for HostSocks {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Handle one SOCKS5 connection: complete the handshake then pipe to `target_port`.
async fn serve_socks5(stream: TcpStream, target_port: u16) -> SocksResult<()> {
    let (proto, cmd, _target_addr) = Socks5ServerProtocol::accept_no_auth(stream)
        .await?
        .read_command()
        .await?
        .resolve_dns()
        .await?;

    match cmd {
        Socks5Command::TCPConnect => {
            // Ignore the SOCKS CONNECT target — always pipe to the in-process
            // HostHttps so the test stays self-contained. Microsandbox intercepts
            // transparently and substitutes secrets before bytes leave the host.
            let target = TargetAddr::Ip(SocketAddr::from((Ipv4Addr::LOCALHOST, target_port)));
            run_tcp_proxy(proto, &target, std::time::Duration::from_secs(30), false).await?;
        }
        _ => {
            proto
                .reply_error(&fast_socks5::ReplyError::CommandNotSupported)
                .await?;
        }
    }
    Ok(())
}

async fn receive_https_request(
    mut stream: tokio_rustls::server::TlsStream<TcpStream>,
) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    loop {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before headers",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        .await?;
    stream.shutdown().await?;
    Ok(buf)
}

fn test_server_config() -> Arc<rustls::ServerConfig> {
    let key_pair = rcgen::KeyPair::generate().expect("generate key");
    let params = CertificateParams::new(vec![HOST_ALIAS.to_string()]).expect("cert params");
    let cert = params.self_signed(&key_pair).expect("self-sign");
    let chain = vec![CertificateDer::from(cert.der().to_vec())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("server config"),
    )
}

async fn teardown(sb: Sandbox, name: &str) {
    sb.stop_and_wait().await.expect("stop");
    let _ = Sandbox::remove(name).await;
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

/// Guest routes HTTPS through a SOCKS5 proxy; secret must be substituted.
#[msb_test]
async fn socks5_substitutes_secret_in_authorization_header() {
    let mut server = HostHttps::start().await.expect("https fixture");
    let https_port = server.port();
    let socks = HostSocks::start(https_port).await.expect("socks fixture");
    let socks_port = socks.port();
    let name = "socks5-secret-auth";

    let sb = Sandbox::builder(name)
        .image(CURL_IMAGE)
        .cpus(1)
        .memory(256)
        .user("0")
        .replace()
        .secret(|s| {
            s.env("API_KEY")
                .value(REAL_SECRET)
                .allow_host(HOST_ALIAS)
                .inject_headers(true)
        })
        .network(|n| {
            n.policy(NetworkPolicy::allow_all())
                .tls(|t| t.intercepted_ports(vec![https_port]).verify_upstream(false))
        })
        .create()
        .await
        .expect("create sandbox");

    let out = sb
        .shell(format!(
            r#"set -eu
curl -k --http1.1 -m 30 -sS -o /dev/null \
  -w 'code=%{{http_code}}' \
  --socks5-hostname {HOST_ALIAS}:{socks_port} \
  -H "Authorization: Bearer $API_KEY" \
  https://{HOST_ALIAS}:{https_port}/
"#
        ))
        .await
        .expect("shell");

    let stdout = out.stdout().expect("utf8 stdout");
    assert!(
        stdout.contains("code=200"),
        "expected 200, got: {stdout}\nstderr: {}",
        out.stderr().unwrap_or_default()
    );

    let headers = server.received_headers().await.expect("read headers");
    let headers_str = String::from_utf8_lossy(&headers);
    assert!(
        headers_str.contains(&format!("Authorization: Bearer {REAL_SECRET}")),
        "real secret must reach server, got:\n{headers_str}"
    );
    assert!(
        !headers_str.contains("$MSB_"),
        "placeholder must not reach server, got:\n{headers_str}"
    );

    teardown(sb, name).await;
}

/// Guest routes HTTPS through a SOCKS5 proxy with no secret configured;
/// the plain relay must complete successfully.
#[msb_test]
async fn socks5_plain_relay_without_secrets() {
    let mut server = HostHttps::start().await.expect("https fixture");
    let https_port = server.port();
    let socks = HostSocks::start(https_port).await.expect("socks fixture");
    let socks_port = socks.port();
    let name = "socks5-plain-relay";

    eprintln!("[test] https_port={https_port} socks_port={socks_port}");

    let sb = Sandbox::builder(name)
        .image(CURL_IMAGE)
        .cpus(1)
        .memory(256)
        .user("0")
        .replace()
        .network(|n| {
            n.policy(NetworkPolicy::allow_all())
                .tls(|t| t.intercepted_ports(vec![https_port]).verify_upstream(false))
        })
        .create()
        .await
        .expect("create sandbox");

    eprintln!("[test] sandbox created, calling shell");
    let out = sb
        .shell(format!(
            r#"set -eu
echo RUNNING >&2
curl -k --http1.1 -m 30 -v -o /dev/null \
  -w 'code=%{{http_code}}' \
  --socks5-hostname {HOST_ALIAS}:{socks_port} \
  https://{HOST_ALIAS}:{https_port}/
"#
        ))
        .await
        .expect("shell");
    eprintln!(
        "[test] shell returned stdout={:?} stderr={:?}",
        out.stdout(),
        out.stderr()
    );

    let stdout = out.stdout().expect("utf8 stdout");
    assert!(
        stdout.contains("code=200"),
        "expected 200, got: {stdout}\nstderr: {}",
        out.stderr().unwrap_or_default()
    );

    let headers = server.received_headers().await.expect("read headers");
    assert!(!headers.is_empty(), "server should receive a request");

    teardown(sb, name).await;
}

/// Guest routes HTTPS through a SOCKS4a proxy; secret must be substituted.
#[msb_test]
async fn socks4a_substitutes_secret_in_authorization_header() {
    let mut server = HostHttps::start().await.expect("https fixture");
    let https_port = server.port();
    let socks = HostSocks::start(https_port).await.expect("socks fixture");
    let socks_port = socks.port();
    let name = "socks4a-secret-auth";

    let sb = Sandbox::builder(name)
        .image(CURL_IMAGE)
        .cpus(1)
        .memory(256)
        .user("0")
        .replace()
        .secret(|s| {
            s.env("API_KEY")
                .value(REAL_SECRET)
                .allow_host(HOST_ALIAS)
                .inject_headers(true)
        })
        .network(|n| {
            n.policy(NetworkPolicy::allow_all())
                .tls(|t| t.intercepted_ports(vec![https_port]).verify_upstream(false))
        })
        .create()
        .await
        .expect("create sandbox");

    let out = sb
        .shell(format!(
            r#"set -eu
curl -k --http1.1 -m 30 -sS -o /dev/null \
  -w 'code=%{{http_code}}' \
  --socks4a {HOST_ALIAS}:{socks_port} \
  -H "Authorization: Bearer $API_KEY" \
  https://{HOST_ALIAS}:{https_port}/
"#
        ))
        .await
        .expect("shell");

    let stdout = out.stdout().expect("utf8 stdout");
    assert!(
        stdout.contains("code=200"),
        "expected 200, got: {stdout}\nstderr: {}",
        out.stderr().unwrap_or_default()
    );

    let headers = server.received_headers().await.expect("read headers");
    let headers_str = String::from_utf8_lossy(&headers);
    assert!(
        headers_str.contains(&format!("Authorization: Bearer {REAL_SECRET}")),
        "real secret must reach server, got:\n{headers_str}"
    );
    assert!(
        !headers_str.contains("$MSB_"),
        "placeholder must not reach server, got:\n{headers_str}"
    );

    teardown(sb, name).await;
}

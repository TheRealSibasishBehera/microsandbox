//! End-to-end IPv6 connectivity tests.
//!
//! All tests below are expected to fail until the virtual network gateway
//! handles Router Solicitations. Without a Router Advertisement response,
//! the guest's IPv6 address stays permanently `tentative` and the kernel
//! drops all outbound IPv6 traffic.
//!
//! To run: cargo nextest run -p microsandbox --tests --run-ignored=only \
//!                           -E 'test(ipv6)'

use microsandbox::{NetworkPolicy, Sandbox};
use test_utils::msb_test;

async fn teardown(sb: Sandbox, name: &str) {
    sb.stop_and_wait().await.expect("stop");
    let _ = Sandbox::remove(name).await;
}

async fn spawn(name: &str) -> Sandbox {
    Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(256)
        .replace()
        .network(|n| n.policy(NetworkPolicy::allow_all()))
        .create()
        .await
        .expect("create sandbox")
}

/// Diagnostic: print the guest's interface config and confirm IPv6 was provisioned.
///
/// Expected output: `fd42:6d73:62:N::2/64` present but marked `tentative`.
/// Always passes — run this first to confirm the environment has IPv6.
#[msb_test]
async fn ipv6_addresses_are_provisioned() {
    let name = "ipv6-addrs";
    let sb = spawn(name).await;

    let out = sb
        .shell("ip addr show eth0 && echo '---' && cat /etc/resolv.conf")
        .await
        .expect("shell");

    let stdout = out.stdout().unwrap_or_default();
    teardown(sb, name).await;

    eprintln!("{stdout}");
    assert!(
        stdout.contains("fd42:"),
        "expected IPv6 address (fd42:...) to be provisioned on eth0, got:\n{stdout}"
    );
}

/// Guest can open a TCP connection to a public IPv6 address.
///
/// `nc -z` to Cloudflare's IPv6 DNS on port 53 — raw TCP, no proxy involved.
#[msb_test]
async fn guest_tcp_connect_ipv6() {
    let name = "ipv6-tcp";
    let sb = spawn(name).await;

    let out = sb
        .shell("nc -z -w 5 2606:4700:4700::1111 53")
        .await
        .expect("shell");

    let success = out.status().success;
    teardown(sb, name).await;

    assert!(success, "nc TCP connect to 2606:4700:4700::1111:53 failed");
}

/// Guest can complete an HTTP request over IPv6.
///
/// `curl --ipv6` to Cloudflare's IPv6 DNS address directly — proves a full
/// HTTP exchange works, not just TCP handshake.
#[msb_test]
async fn guest_http_over_ipv6() {
    let name = "ipv6-http";
    let sb = spawn(name).await;

    let out = sb
        .shell("apk add --no-cache curl -q && curl --ipv6 -g --max-time 10 -sSo /dev/null -w '%{http_code}' 'http://[2606:4700:4700::1111]/dns-query'")
        .await
        .expect("shell");

    let stdout = out.stdout().unwrap_or_default();
    let http_code: u16 = stdout.trim().parse().unwrap_or(0);
    teardown(sb, name).await;

    assert!(
        (200..500).contains(&http_code),
        "expected an HTTP response from [2606:4700:4700::1111], got: {stdout:?}"
    );
}

/// Guest can send ICMPv6 to a public IPv6 address.
#[msb_test]
async fn guest_ping6_internet() {
    let name = "ipv6-ping";
    let sb = spawn(name).await;

    let out = sb
        .shell("ping6 -c 1 -W 5 2606:4700:4700::1111")
        .await
        .expect("shell");

    let success = out.status().success;
    teardown(sb, name).await;

    assert!(success, "ping6 to 2606:4700:4700::1111 failed");
}

/// Guest can reach the sandbox host via `host.microsandbox.internal` over IPv6.
///
/// Validates the gateway path specifically, without depending on internet routing.
#[msb_test]
async fn guest_ping6_host_alias() {
    let name = "ipv6-host-alias";
    let sb = spawn(name).await;

    let out = sb
        .shell("ping6 -c 1 -W 5 host.microsandbox.internal")
        .await
        .expect("shell");

    let success = out.status().success;
    teardown(sb, name).await;

    assert!(success, "ping6 to host.microsandbox.internal failed");
}

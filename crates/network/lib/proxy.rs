//! Bidirectional TCP proxy: smoltcp socket ↔ channels ↔ tokio socket.
//!
//! Each outbound guest TCP connection gets a proxy task that opens a real
//! TCP connection to the destination via tokio and relays data between the
//! channel pair (connected to the smoltcp socket in the poll loop) and the
//! real server.
//!
//! When a SOCKS4/4a or SOCKS5 handshake is detected on any port, the proxy
//! transparently negotiates the SOCKS tunnel, extracts the inner target
//! address, and — if the resulting port is intercepted — hands off to
//! `spawn_tls_proxy` so secret substitution runs on the inner TLS stream.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::policy::{EgressEvaluation, HostnameSource, NetworkPolicy, Protocol};
use crate::shared::SharedState;
use crate::stack::GatewayIps;
use crate::tls::proxy as tls_proxy;
use crate::tls::sni;
use crate::tls::state::TlsState;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Buffer size for reading from the real server.
const SERVER_READ_BUF_SIZE: usize = 16384;

/// Max bytes to buffer while peeking for the ClientHello's SNI.
const PEEK_BUF_SIZE: usize = 16384;

/// Upper bound on time spent buffering the first flight before
/// falling back to a cache-only egress decision.
const PEEK_BUDGET: Duration = Duration::from_secs(5);

/// `host.microsandbox.internal` — guest DNS synthesises an A record pointing
/// to the gateway; the host side rewrites that IP to loopback.
const HOST_ALIAS: &str = "host.microsandbox.internal";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Byte-at-a-time reader backed by an owned `mpsc` channel of `Bytes` chunks.
///
/// Used by the SOCKS negotiation helpers so they can call `read_u8()` /
/// `read_exact()` on the channel stream. After negotiation completes, call
/// `into_parts()` to retrieve the receiver and any leftover bytes that belong
/// to the inner (post-handshake) stream.
struct ChannelReader {
    rx: mpsc::Receiver<Bytes>,
    leftover: Bytes,
}

impl ChannelReader {
    fn new(rx: mpsc::Receiver<Bytes>) -> Self {
        Self {
            rx,
            leftover: Bytes::new(),
        }
    }

    /// Decompose into the underlying receiver and any bytes already buffered
    /// beyond the SOCKS handshake. Both must be prepended to the inner stream.
    fn into_parts(self) -> (mpsc::Receiver<Bytes>, Bytes) {
        (self.rx, self.leftover)
    }

    async fn read_u8(&mut self) -> io::Result<u8> {
        let mut b = [0u8; 1];
        self.read_exact(&mut b).await?;
        Ok(b[0])
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let mut written = 0;
        while written < buf.len() {
            if self.leftover.is_empty() {
                match self.rx.recv().await {
                    Some(chunk) => self.leftover = chunk,
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "channel closed during SOCKS negotiation",
                        ));
                    }
                }
            }
            let need = buf.len() - written;
            let have = self.leftover.len();
            let take = need.min(have);
            buf[written..written + take].copy_from_slice(&self.leftover[..take]);
            self.leftover = self.leftover.slice(take..);
            written += take;
        }
        Ok(())
    }

    /// Read a NUL-terminated byte string (SOCKS4 USERID / domain fields).
    async fn read_nul_string(&mut self) -> io::Result<Vec<u8>> {
        let mut s = Vec::new();
        loop {
            let b = self.read_u8().await?;
            if b == 0 {
                break;
            }
            s.push(b);
        }
        Ok(s)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Spawn a TCP proxy task for a newly established connection.
///
/// `guest_dst` is what the guest dialed — the address policy rules
/// match against. `connect_dst` is the host-side address tokio actually
/// dials; for host-alias connections it's loopback (gateway rewritten).
/// For everything else the two are identical.
///
/// `upstream_connected` is flipped to `true` after the upstream
/// `TcpStream::connect` succeeds. The connection tracker reads this
/// on proxy exit to decide between FIN (clean close) and RST
/// (upstream never reached, e.g. connect failure or policy denial).
#[allow(clippy::too_many_arguments)]
pub fn spawn_tcp_proxy(
    handle: &tokio::runtime::Handle,
    guest_dst: SocketAddr,
    connect_dst: SocketAddr,
    from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
    network_policy: Arc<NetworkPolicy>,
    tls_state: Option<Arc<TlsState>>,
    gateway: GatewayIps,
    upstream_connected: Arc<AtomicBool>,
) {
    handle.spawn(async move {
        if let Err(e) = tcp_proxy_task(
            guest_dst,
            connect_dst,
            from_smoltcp,
            to_smoltcp,
            shared,
            network_policy,
            tls_state,
            gateway,
            upstream_connected,
        )
        .await
        {
            tracing::debug!(dst = %connect_dst, error = %e, "TCP proxy task ended");
        }
    });
}

/// Core TCP proxy: peek for SOCKS / SNI, evaluate egress policy, then either
/// connect and relay or drop the channels.
#[allow(clippy::too_many_arguments)]
async fn tcp_proxy_task(
    guest_dst: SocketAddr,
    connect_dst: SocketAddr,
    mut from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
    network_policy: Arc<NetworkPolicy>,
    tls_state: Option<Arc<TlsState>>,
    gateway: GatewayIps,
    upstream_connected: Arc<AtomicBool>,
) -> io::Result<()> {
    // Peek at the very first byte unconditionally to detect SOCKS handshakes.
    // This must happen BEFORE peek_for_sni, which is only called when domain
    // rules are configured and would silently miss SOCKS traffic otherwise.
    //
    // We read one byte directly from the channel (without ChannelReader) so
    // we can move from_smoltcp into the SOCKS handlers without a live borrow.
    let first_byte = {
        // Read the first available chunk, take one byte, put the rest back
        // by re-creating a channel with the remainder prepended.
        let first_chunk = match from_smoltcp.recv().await {
            Some(c) => c,
            None => return Ok(()), // channel closed before any data
        };
        let first_byte = first_chunk[0];
        if first_chunk.len() > 1 {
            // Put the remainder back into a new channel so the receiver we
            // pass to SOCKS handlers / peek_for_sni sees a contiguous stream.
            let remainder = first_chunk.slice(1..);
            let (tx_prepend, rx_prepend) = mpsc::channel::<Bytes>(64);
            // This send cannot block — capacity is 64 and we just created it.
            let _ = tx_prepend.try_send(remainder);
            // Forward the rest of from_smoltcp into the new channel.
            tokio::spawn(async move {
                while let Some(chunk) = from_smoltcp.recv().await {
                    if tx_prepend.send(chunk).await.is_err() {
                        break;
                    }
                }
            });
            from_smoltcp = rx_prepend;
        }
        first_byte
    };

    match first_byte {
        0x04 => {
            // SOCKS4 / SOCKS4a — hand ownership of the channel to the reader.
            return handle_socks4(
                ChannelReader::new(from_smoltcp),
                to_smoltcp,
                shared,
                network_policy,
                tls_state,
                gateway,
                upstream_connected,
            )
            .await;
        }
        0x05 => {
            // SOCKS5
            return handle_socks5(
                ChannelReader::new(from_smoltcp),
                to_smoltcp,
                shared,
                network_policy,
                tls_state,
                gateway,
                upstream_connected,
            )
            .await;
        }
        _ => {}
    }

    // Not a SOCKS handshake — reconstruct the initial byte so the existing
    // SNI-peek / egress / relay path sees a complete stream.
    let first_chunk = Bytes::copy_from_slice(&[first_byte]);
    // Put it back as the head of initial_buf, then continue to SNI peek.
    let (initial_buf, sni) = if network_policy.has_domain_rules() {
        let (rest, sni) = peek_for_sni(&mut from_smoltcp, PEEK_BUF_SIZE, PEEK_BUDGET).await;
        let mut buf = Vec::with_capacity(1 + rest.len());
        buf.extend_from_slice(&first_chunk);
        buf.extend_from_slice(&rest);
        (buf, sni)
    } else {
        (first_chunk.to_vec(), None)
    };

    // Re-evaluate egress against the *guest* dst.
    if network_policy.has_domain_rules() {
        let source = match sni.as_deref() {
            Some(name) => HostnameSource::Sni(name),
            None => HostnameSource::CacheOnly,
        };
        match network_policy.evaluate_egress_with_source(guest_dst, Protocol::Tcp, &shared, source)
        {
            EgressEvaluation::Allow => {}
            EgressEvaluation::Deny => {
                tracing::debug!(
                    dst = %guest_dst,
                    source = source.label(),
                    "TCP egress denied by domain policy",
                );
                return Ok(());
            }
            EgressEvaluation::DeferUntilHostname => {
                debug_assert!(false, "DeferUntilHostname leaked into TCP proxy task");
                return Ok(());
            }
        }
    }

    let stream = TcpStream::connect(connect_dst).await?;
    upstream_connected.store(true, Ordering::Release);
    let (mut server_rx, mut server_tx) = stream.into_split();

    // Replay the buffered first flight before relay starts.
    if !initial_buf.is_empty()
        && let Err(e) = server_tx.write_all(&initial_buf).await
    {
        tracing::debug!(dst = %connect_dst, error = %e, "replay of buffered first flight failed");
        return Ok(());
    }
    // Allow initial_buf to be dropped — no longer needed.
    drop(initial_buf);

    let mut server_buf = vec![0u8; SERVER_READ_BUF_SIZE];

    loop {
        tokio::select! {
            data = from_smoltcp.recv() => {
                match data {
                    Some(bytes) => {
                        if let Err(e) = server_tx.write_all(&bytes).await {
                            tracing::debug!(dst = %connect_dst, error = %e, "write to server failed");
                            break;
                        }
                    }
                    None => break,
                }
            }

            result = server_rx.read(&mut server_buf) => {
                match result {
                    Ok(0) => break,
                    Ok(n) => {
                        let data = Bytes::copy_from_slice(&server_buf[..n]);
                        if to_smoltcp.send(data).await.is_err() {
                            break;
                        }
                        shared.proxy_wake.wake();
                    }
                    Err(e) => {
                        tracing::debug!(dst = %connect_dst, error = %e, "read from server failed");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Handle a SOCKS4/4a handshake that was already detected via the first byte
/// (`0x04`).
///
/// Wire format (SOCKS4 CONNECT request):
///   VN(1)=4  CD(1)=1  DSTPORT(2)  DSTIP(4)  USERID(var+NUL)  [DOMAIN(var+NUL) if 4a]
///
/// The first byte (VN=0x04) has already been consumed by the caller.
#[allow(clippy::too_many_arguments)]
async fn handle_socks4(
    mut reader: ChannelReader,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
    network_policy: Arc<NetworkPolicy>,
    tls_state: Option<Arc<TlsState>>,
    gateway: GatewayIps,
    upstream_connected: Arc<AtomicBool>,
) -> io::Result<()> {
    // CD (command)
    let cd = reader.read_u8().await?;
    if cd != 0x01 {
        // Only CONNECT (0x01) is relevant; BIND not supported.
        // Send a rejection and close.
        let _ = to_smoltcp
            .send(Bytes::from_static(&[0x00, 0x5b, 0, 0, 0, 0, 0, 0]))
            .await;
        return Ok(());
    }

    // DSTPORT (big-endian u16)
    let mut port_bytes = [0u8; 2];
    reader.read_exact(&mut port_bytes).await?;
    let dst_port = u16::from_be_bytes(port_bytes);

    // DSTIP (4 bytes)
    let mut ip_bytes = [0u8; 4];
    reader.read_exact(&mut ip_bytes).await?;
    let dst_ip = Ipv4Addr::from(ip_bytes);

    // USERID (NUL-terminated, discarded)
    reader.read_nul_string().await?;

    // Detect SOCKS4a: DSTIP is 0.0.0.x (non-routable marker)
    let target_host =
        if ip_bytes[0] == 0 && ip_bytes[1] == 0 && ip_bytes[2] == 0 && ip_bytes[3] != 0 {
            // SOCKS4a: domain follows USERID, also NUL-terminated.
            let domain_bytes = reader.read_nul_string().await?;
            match String::from_utf8(domain_bytes) {
                Ok(s) => s,
                Err(_) => {
                    let _ = to_smoltcp
                        .send(Bytes::from_static(&[0x00, 0x5b, 0, 0, 0, 0, 0, 0]))
                        .await;
                    return Ok(());
                }
            }
        } else {
            dst_ip.to_string()
        };

    // Acknowledge CONNECT request: VN=0 CD=0x5a (granted) PORT=0 IP=0.0.0.0
    to_smoltcp
        .send(Bytes::from_static(&[0x00, 0x5a, 0, 0, 0, 0, 0, 0]))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "to_smoltcp closed"))?;
    shared.proxy_wake.wake();

    let (from_smoltcp, leftover) = reader.into_parts();

    dispatch_socks_tunnel(
        target_host,
        dst_port,
        leftover,
        from_smoltcp,
        to_smoltcp,
        shared,
        network_policy,
        tls_state,
        gateway,
        upstream_connected,
    )
    .await
}

/// Handle a SOCKS5 handshake that was already detected via the first byte
/// (`0x05`).
///
/// Negotiates auth method (no-auth only), reads the CONNECT command, sends
/// a success reply, then dispatches the inner stream.
#[allow(clippy::too_many_arguments)]
async fn handle_socks5(
    mut reader: ChannelReader,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
    network_policy: Arc<NetworkPolicy>,
    tls_state: Option<Arc<TlsState>>,
    gateway: GatewayIps,
    upstream_connected: Arc<AtomicBool>,
) -> io::Result<()> {
    // --- Auth sub-negotiation ---
    // NMETHODS(1)  METHODS(NMETHODS)
    let nmethods = reader.read_u8().await? as usize;
    let mut methods = vec![0u8; nmethods];
    reader.read_exact(&mut methods).await?;

    if !methods.contains(&0x00) {
        // No acceptable auth method — send 0xFF (no acceptable method) and close.
        let _ = to_smoltcp.send(Bytes::from_static(&[0x05, 0xFF])).await;
        return Ok(());
    }
    // Select no-auth (0x00).
    to_smoltcp
        .send(Bytes::from_static(&[0x05, 0x00]))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "to_smoltcp closed"))?;
    shared.proxy_wake.wake();

    // --- CONNECT request ---
    // VER(1)=5  CMD(1)  RSV(1)=0  ATYP(1)  DST.ADDR(var)  DST.PORT(2)
    let ver = reader.read_u8().await?;
    let cmd = reader.read_u8().await?;
    let _rsv = reader.read_u8().await?;
    let atyp = reader.read_u8().await?;

    if ver != 0x05 || cmd != 0x01 {
        // Reject non-CONNECT or wrong version.
        let _ = to_smoltcp
            .send(Bytes::from_static(&[
                0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
            ]))
            .await;
        return Ok(());
    }

    let target_host = match atyp {
        0x01 => {
            // IPv4
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).await?;
            Ipv4Addr::from(buf).to_string()
        }
        0x03 => {
            // Domain name: LEN(1) + bytes
            let len = reader.read_u8().await? as usize;
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf).await?;
            match String::from_utf8(buf) {
                Ok(s) => s,
                Err(_) => {
                    let _ = to_smoltcp
                        .send(Bytes::from_static(&[
                            0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
                        ]))
                        .await;
                    return Ok(());
                }
            }
        }
        0x04 => {
            // IPv6
            let mut buf = [0u8; 16];
            reader.read_exact(&mut buf).await?;
            Ipv6Addr::from(buf).to_string()
        }
        _ => {
            let _ = to_smoltcp
                .send(Bytes::from_static(&[
                    0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
                ]))
                .await;
            return Ok(());
        }
    };

    let mut port_bytes = [0u8; 2];
    reader.read_exact(&mut port_bytes).await?;
    let dst_port = u16::from_be_bytes(port_bytes);

    // Reply: VER CMD RSV ATYP BND.ADDR BND.PORT (all-zero is fine for our use)
    to_smoltcp
        .send(Bytes::from_static(&[
            0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
        ]))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "to_smoltcp closed"))?;
    shared.proxy_wake.wake();

    let (from_smoltcp, leftover) = reader.into_parts();

    dispatch_socks_tunnel(
        target_host,
        dst_port,
        leftover,
        from_smoltcp,
        to_smoltcp,
        shared,
        network_policy,
        tls_state,
        gateway,
        upstream_connected,
    )
    .await
}

/// After a SOCKS handshake completes, resolve the inner target and dispatch
/// to either `spawn_tls_proxy` (intercepted ports) or a plain relay.
///
/// `leftover` contains any bytes already consumed from `from_smoltcp` by the
/// SOCKS negotiation that belong to the inner stream. These must be replayed
/// before the relay starts. For plain relay they are written to the upstream
/// socket; for TLS interception they are prepended back onto the channel.
#[allow(clippy::too_many_arguments)]
async fn dispatch_socks_tunnel(
    target_host: String,
    target_port: u16,
    leftover: Bytes,
    mut from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
    network_policy: Arc<NetworkPolicy>,
    tls_state: Option<Arc<TlsState>>,
    gateway: GatewayIps,
    upstream_connected: Arc<AtomicBool>,
) -> io::Result<()> {
    let connect_dst = resolve_socks_dst(&target_host, target_port, gateway)?;

    // Check whether this port should be TLS-intercepted.
    let should_intercept = tls_state
        .as_ref()
        .is_some_and(|ts| ts.config.intercepted_ports.contains(&target_port));

    if should_intercept {
        let ts = tls_state.unwrap();
        // If the negotiation left bytes buffered, replay them into the channel
        // before handing the receiver to spawn_tls_proxy.
        let (final_rx, final_tx) = if !leftover.is_empty() {
            // Create a new channel pair; prepend leftover then re-forward from_smoltcp.
            let (tx_new, rx_new) = mpsc::channel::<Bytes>(64);
            tx_new
                .send(leftover)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "channel closed"))?;
            // Forward the rest of from_smoltcp in a background task.
            tokio::spawn(async move {
                let mut rx = from_smoltcp;
                while let Some(chunk) = rx.recv().await {
                    if tx_new.send(chunk).await.is_err() {
                        break;
                    }
                }
            });
            (rx_new, to_smoltcp)
        } else {
            (from_smoltcp, to_smoltcp)
        };

        // guest_dst for the TLS proxy is the SOCKS target as seen by the guest
        // (so policy rules match the right name/IP). connect_dst is the resolved
        // host-side address. For the host alias, restore the gateway IP so that
        // SecretsHandler::host_alias_matches can verify the connection identity —
        // it compares guest_ip against gateway_ipv4/ipv6, not against loopback.
        let socks_guest_ip = if target_host.eq_ignore_ascii_case(HOST_ALIAS) {
            gateway
                .ipv4
                .map(IpAddr::V4)
                .or_else(|| gateway.ipv6.map(IpAddr::V6))
                .unwrap_or(connect_dst.ip())
        } else {
            connect_dst.ip()
        };
        let socks_guest_dst = SocketAddr::new(socks_guest_ip, target_port);
        let handle = tls_proxy::spawn_tls_proxy(
            &tokio::runtime::Handle::current(),
            socks_guest_dst,
            connect_dst,
            final_rx,
            final_tx,
            shared,
            ts,
            network_policy,
            upstream_connected,
        );
        let _ = handle.await;
        return Ok(());
    }

    // Plain TCP relay for the inner stream.
    let stream = TcpStream::connect(connect_dst).await?;
    upstream_connected.store(true, Ordering::Release);
    let (mut server_rx, mut server_tx) = stream.into_split();

    // Replay any leftover bytes from the SOCKS negotiation.
    if !leftover.is_empty()
        && let Err(e) = server_tx.write_all(&leftover).await
    {
        tracing::debug!(dst = %connect_dst, error = %e, "SOCKS leftover replay failed");
        return Ok(());
    }

    let mut server_buf = vec![0u8; SERVER_READ_BUF_SIZE];

    loop {
        tokio::select! {
            data = from_smoltcp.recv() => {
                match data {
                    Some(bytes) => {
                        if let Err(e) = server_tx.write_all(&bytes).await {
                            tracing::debug!(dst = %connect_dst, error = %e, "SOCKS relay write failed");
                            break;
                        }
                    }
                    None => break,
                }
            }
            result = server_rx.read(&mut server_buf) => {
                match result {
                    Ok(0) => break,
                    Ok(n) => {
                        let data = Bytes::copy_from_slice(&server_buf[..n]);
                        if to_smoltcp.send(data).await.is_err() {
                            break;
                        }
                        shared.proxy_wake.wake();
                    }
                    Err(e) => {
                        tracing::debug!(dst = %connect_dst, error = %e, "SOCKS relay read failed");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Resolve a SOCKS target (hostname + port) to a `SocketAddr` for dialing.
///
/// Handles the `HOST_ALIAS` special case: rewrites the gateway's synthetic
/// hostname to loopback so `host.microsandbox.internal` connects to the
/// host's loopback interface.
fn resolve_socks_dst(host: &str, port: u16, gateway: GatewayIps) -> io::Result<SocketAddr> {
    if host.eq_ignore_ascii_case(HOST_ALIAS) {
        return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    }

    // Try to parse as a bare IP address first.
    if let Ok(ip) = host.parse::<IpAddr>() {
        let addr = SocketAddr::new(ip, port);
        // Apply gateway → loopback rewrite for IP addresses too.
        return Ok(rewrite_gateway(addr, gateway));
    }

    // Synchronous DNS resolution via the standard library.
    // This runs on the tokio thread pool's blocking threads.
    let addrs: Vec<SocketAddr> = std::net::ToSocketAddrs::to_socket_addrs(&(host, port))
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("SOCKS DNS resolve '{host}:{port}': {e}"),
            )
        })?
        .collect();

    addrs
        .into_iter()
        .map(|a| rewrite_gateway(a, gateway))
        .next()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("SOCKS DNS resolve '{host}:{port}': no addresses"),
            )
        })
}

/// Apply the gateway → loopback rewrite to a resolved address.
fn rewrite_gateway(addr: SocketAddr, gateway: GatewayIps) -> SocketAddr {
    match addr.ip() {
        IpAddr::V4(v4) if gateway.ipv4 == Some(v4) => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
        }
        IpAddr::V6(v6) if gateway.ipv6 == Some(v6) => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), addr.port())
        }
        _ => addr,
    }
}

/// Buffer the first flight until SNI can be extracted, or until one
/// of the bail-out conditions hits (channel close, buffer cap,
/// timeout). Never errors; non-TLS / slow / malformed input all
/// fall through to `None`.
///
/// On hit, the SNI is canonicalized (lowercase + trim trailing dot)
/// for byte-equal matching against rule destinations. The returned
/// buffer must be replayed verbatim to upstream before the caller
/// starts its relay loop.
async fn peek_for_sni(
    rx: &mut mpsc::Receiver<Bytes>,
    max: usize,
    budget: Duration,
) -> (Vec<u8>, Option<String>) {
    let mut buf = Vec::with_capacity(PEEK_BUF_SIZE.min(8192));
    let timeout_fut = tokio::time::sleep(budget);
    tokio::pin!(timeout_fut);

    let raw_sni = loop {
        tokio::select! {
            biased;
            _ = &mut timeout_fut => break None,
            data = rx.recv() => {
                match data {
                    Some(bytes) => {
                        buf.extend_from_slice(&bytes);
                        // First byte of a TLS record is the ContentType;
                        // 0x16 is handshake. Anything else can't be a
                        // ClientHello, so don't burn the full budget on
                        // plain HTTP / SSH / etc.
                        if buf.first() != Some(&0x16) {
                            break None;
                        }
                        if let Some(name) = sni::extract_sni(&buf) {
                            break Some(name);
                        }
                        if buf.len() >= max {
                            break None;
                        }
                    }
                    None => break None,
                }
            }
        }
    };

    let canonical = raw_sni.map(|s| s.trim_end_matches('.').to_ascii_lowercase());
    (buf, canonical)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic TLS ClientHello carrying SNI `example.com`. Bytes
    /// borrowed from `tls::sni` test fixtures so the parser sees a
    /// well-formed record.
    fn synthetic_client_hello(sni: &str) -> Vec<u8> {
        // Minimal but valid TLS 1.2 ClientHello with one SNI entry.
        // Layout: record header (5) + handshake header (4) + body.
        let host_bytes = sni.as_bytes();
        let host_len = host_bytes.len() as u16;
        let server_name_list_len = 3 + host_len; // type(1) + len(2) + host
        let extension_data_len = 2 + server_name_list_len; // list-len(2) + list
        let extensions_total = 4 + extension_data_len; // type(2) + len(2) + data

        let mut body = Vec::new();
        // Client version
        body.extend_from_slice(&[0x03, 0x03]);
        // Random (32 bytes)
        body.extend_from_slice(&[0u8; 32]);
        // Session id length + (empty)
        body.push(0);
        // Cipher suites length + one cipher
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]);
        // Compression methods length + null
        body.extend_from_slice(&[0x01, 0x00]);
        // Extensions length
        body.extend_from_slice(&extensions_total.to_be_bytes());
        // SNI extension: type 0x0000
        body.extend_from_slice(&[0x00, 0x00]);
        body.extend_from_slice(&extension_data_len.to_be_bytes());
        body.extend_from_slice(&server_name_list_len.to_be_bytes());
        body.push(0x00); // host_name type
        body.extend_from_slice(&host_len.to_be_bytes());
        body.extend_from_slice(host_bytes);

        let handshake_len = body.len() as u32;
        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        hs.extend_from_slice(&handshake_len.to_be_bytes()[1..]); // 24-bit length
        hs.extend_from_slice(&body);

        let record_len = hs.len() as u16;
        let mut record = Vec::new();
        record.extend_from_slice(&[0x16, 0x03, 0x01]); // Handshake, TLS 1.0
        record.extend_from_slice(&record_len.to_be_bytes());
        record.extend_from_slice(&hs);

        record
    }

    #[tokio::test]
    async fn peek_for_sni_extracts_and_canonicalizes() {
        let (tx, mut rx) = mpsc::channel(4);
        let hello = synthetic_client_hello("Example.COM");
        tx.send(Bytes::from(hello.clone())).await.unwrap();
        drop(tx); // close so peek returns even if SNI didn't satisfy

        let (buf, sni) = peek_for_sni(&mut rx, PEEK_BUF_SIZE, PEEK_BUDGET).await;
        assert_eq!(sni.as_deref(), Some("example.com"));
        assert_eq!(buf, hello);
    }

    #[tokio::test]
    async fn peek_for_sni_returns_none_on_channel_close_without_data() {
        let (tx, mut rx) = mpsc::channel::<Bytes>(1);
        drop(tx);
        let (buf, sni) = peek_for_sni(&mut rx, PEEK_BUF_SIZE, PEEK_BUDGET).await;
        assert!(buf.is_empty());
        assert_eq!(sni, None);
    }

    #[tokio::test]
    async fn peek_for_sni_returns_none_on_non_tls_data() {
        let (tx, mut rx) = mpsc::channel(4);
        // Plaintext HTTP request; not a TLS record so extract_sni returns None.
        tx.send(Bytes::from_static(
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        ))
        .await
        .unwrap();
        drop(tx);
        let (buf, sni) = peek_for_sni(&mut rx, PEEK_BUF_SIZE, PEEK_BUDGET).await;
        assert!(
            !buf.is_empty(),
            "buffered bytes must be returned for replay"
        );
        assert_eq!(sni, None);
    }

    #[tokio::test]
    async fn peek_for_sni_falls_back_on_timeout() {
        let (tx, mut rx) = mpsc::channel::<Bytes>(1);
        // Hold the sender open but send nothing — peek must time out.
        let (buf, sni) = peek_for_sni(&mut rx, PEEK_BUF_SIZE, Duration::from_millis(50)).await;
        drop(tx);
        assert!(buf.is_empty());
        assert_eq!(sni, None);
    }

    #[tokio::test]
    async fn peek_for_sni_caps_at_max_bytes() {
        let (tx, mut rx) = mpsc::channel(4);
        // First byte 0x16 keeps the peek collecting past the early
        // non-TLS bail. Padding bytes are zero so the SNI parser never
        // matches and the loop drives to the size cap.
        let mut first = vec![0u8; 8192];
        first[0] = 0x16;
        tx.send(Bytes::from(first)).await.unwrap();
        tx.send(Bytes::from(vec![0u8; 8192])).await.unwrap();
        tx.send(Bytes::from(vec![0u8; 8192])).await.unwrap();
        drop(tx);

        let (buf, sni) = peek_for_sni(&mut rx, PEEK_BUF_SIZE, PEEK_BUDGET).await;
        assert_eq!(sni, None, "no SNI in non-TLS data");
        assert!(
            buf.len() >= PEEK_BUF_SIZE,
            "buffer must hit the cap before bail-out: got {}",
            buf.len()
        );
    }

    #[tokio::test]
    async fn peek_for_sni_bails_immediately_on_non_tls_first_byte() {
        let (tx, mut rx) = mpsc::channel(4);
        // Plain HTTP request: first byte 'G' (0x47) — clearly not TLS.
        tx.send(Bytes::from_static(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
            .await
            .unwrap();
        drop(tx);

        // 5-second nominal budget; assert we returned in well under
        // that — the early-bail must not wait for the full window.
        let started = std::time::Instant::now();
        let (buf, sni) = peek_for_sni(&mut rx, PEEK_BUF_SIZE, PEEK_BUDGET).await;
        let elapsed = started.elapsed();
        assert_eq!(sni, None);
        assert!(buf.starts_with(b"GET"));
        assert!(
            elapsed < Duration::from_millis(500),
            "non-TLS bail must be fast: took {elapsed:?}"
        );
    }

    //----------------------------------------------------------------------------------------------
    // peek_for_sni × evaluate_egress_with_source — combined integration tests
    //----------------------------------------------------------------------------------------------

    use std::net::IpAddr;
    use std::time::Duration as StdDuration;

    use crate::policy::{Action, Destination, NetworkPolicy, PortRange, Rule};
    use crate::shared::{ResolvedHostnameFamily, SharedState};

    const SHARED_FASTLY_IP: &str = "151.101.0.223";

    fn shared_with(host: &str, ip: &str) -> SharedState {
        let shared = SharedState::new(4);
        shared.cache_resolved_hostname(
            host,
            ResolvedHostnameFamily::Ipv4,
            [ip.parse::<IpAddr>().unwrap()],
            StdDuration::from_secs(60),
        );
        shared
    }

    fn allow_https(domain: &str) -> Rule {
        Rule {
            direction: crate::policy::Direction::Egress,
            destination: Destination::Domain(domain.parse().unwrap()),
            protocols: vec![Protocol::Tcp],
            ports: vec![PortRange::single(443)],
            action: Action::Allow,
        }
    }

    /// Over-allow case: cache says IP X is `pypi.org` (allowed); SNI
    /// is `evil.com`. SNI must override the cache and deny.
    #[tokio::test]
    async fn integration_sni_overrides_cache_for_over_allow() {
        let shared = shared_with("pypi.org", SHARED_FASTLY_IP);
        let policy = NetworkPolicy {
            default_egress: Action::Deny,
            default_ingress: Action::Allow,
            rules: vec![allow_https("pypi.org")],
        };
        let dst = SocketAddr::new(SHARED_FASTLY_IP.parse().unwrap(), 443);

        let (tx, mut rx) = mpsc::channel(4);
        tx.send(Bytes::from(synthetic_client_hello("evil.com")))
            .await
            .unwrap();
        drop(tx);

        let (initial_buf, sni) = peek_for_sni(&mut rx, PEEK_BUF_SIZE, PEEK_BUDGET).await;
        assert_eq!(sni.as_deref(), Some("evil.com"));
        assert!(!initial_buf.is_empty());

        let source = sni
            .as_deref()
            .map(HostnameSource::Sni)
            .unwrap_or(HostnameSource::CacheOnly);
        let eval = policy.evaluate_egress_with_source(dst, Protocol::Tcp, &shared, source);
        assert_eq!(
            eval,
            EgressEvaluation::Deny,
            "SNI=evil.com must not piggy-back on the cached pypi.org match",
        );
    }

    /// Over-block case: cache says IP X is `ads.example.com` (denied);
    /// SNI is `api.example.com`. SNI must override the cache and allow.
    #[tokio::test]
    async fn integration_sni_overrides_cache_for_over_block() {
        let shared = shared_with("ads.example.com", SHARED_FASTLY_IP);
        let policy = NetworkPolicy {
            default_egress: Action::Allow,
            default_ingress: Action::Allow,
            rules: vec![Rule::deny_egress(Destination::Domain(
                "ads.example.com".parse().unwrap(),
            ))],
        };
        let dst = SocketAddr::new(SHARED_FASTLY_IP.parse().unwrap(), 443);

        let (tx, mut rx) = mpsc::channel(4);
        tx.send(Bytes::from(synthetic_client_hello("api.example.com")))
            .await
            .unwrap();
        drop(tx);

        let (_initial_buf, sni) = peek_for_sni(&mut rx, PEEK_BUF_SIZE, PEEK_BUDGET).await;
        assert_eq!(sni.as_deref(), Some("api.example.com"));

        let source = sni
            .as_deref()
            .map(HostnameSource::Sni)
            .unwrap_or(HostnameSource::CacheOnly);
        let eval = policy.evaluate_egress_with_source(dst, Protocol::Tcp, &shared, source);
        assert_eq!(
            eval,
            EgressEvaluation::Allow,
            "SNI=api.example.com must not be caught by the deny on ads.example.com",
        );
    }

    /// Non-TLS first-flight falls back to `CacheOnly`; the cache
    /// match decides.
    #[tokio::test]
    async fn integration_non_tls_falls_back_to_cache() {
        let shared = shared_with("pypi.org", SHARED_FASTLY_IP);
        let policy = NetworkPolicy {
            default_egress: Action::Deny,
            default_ingress: Action::Allow,
            rules: vec![allow_https("pypi.org")],
        };
        let dst = SocketAddr::new(SHARED_FASTLY_IP.parse().unwrap(), 443);

        let (tx, mut rx) = mpsc::channel(4);
        // Plain HTTP request; not a TLS record.
        tx.send(Bytes::from_static(
            b"GET / HTTP/1.1\r\nHost: pypi.org\r\n\r\n",
        ))
        .await
        .unwrap();
        drop(tx);

        let (initial_buf, sni) = peek_for_sni(&mut rx, PEEK_BUF_SIZE, PEEK_BUDGET).await;
        assert_eq!(sni, None, "non-TLS data → no SNI");
        assert!(
            !initial_buf.is_empty(),
            "buffered bytes must survive for replay"
        );

        let source = sni
            .as_deref()
            .map(HostnameSource::Sni)
            .unwrap_or(HostnameSource::CacheOnly);
        let eval = policy.evaluate_egress_with_source(dst, Protocol::Tcp, &shared, source);
        assert_eq!(
            eval,
            EgressEvaluation::Allow,
            "cache-only fallback must still allow the cached hostname's IP",
        );
    }

    /// SNI matches a `DomainSuffix` rule with a cache binding for the
    /// claimed name. Genuine pre-resolved traffic passes.
    #[tokio::test]
    async fn integration_sni_matches_domain_suffix_with_cache_binding() {
        let shared = shared_with("files.pythonhosted.org", SHARED_FASTLY_IP);
        let policy = NetworkPolicy {
            default_egress: Action::Deny,
            default_ingress: Action::Allow,
            rules: vec![Rule {
                direction: crate::policy::Direction::Egress,
                destination: Destination::DomainSuffix(".pythonhosted.org".parse().unwrap()),
                protocols: vec![Protocol::Tcp],
                ports: vec![PortRange::single(443)],
                action: Action::Allow,
            }],
        };
        let dst = SocketAddr::new(SHARED_FASTLY_IP.parse().unwrap(), 443);

        let (tx, mut rx) = mpsc::channel(4);
        tx.send(Bytes::from(synthetic_client_hello(
            "files.pythonhosted.org",
        )))
        .await
        .unwrap();
        drop(tx);

        let (_buf, sni) = peek_for_sni(&mut rx, PEEK_BUF_SIZE, PEEK_BUDGET).await;
        let source = sni
            .as_deref()
            .map(HostnameSource::Sni)
            .unwrap_or(HostnameSource::CacheOnly);
        let eval = policy.evaluate_egress_with_source(dst, Protocol::Tcp, &shared, source);
        assert_eq!(eval, EgressEvaluation::Allow);
    }

    /// Spoofed SNI on an IP with no cache binding for any matching
    /// name: byte-equality with the suffix passes, but no DNS lookup
    /// ever tied a `*.pythonhosted.org` name to the destination, so
    /// the AND-check fails and the connection is denied.
    #[tokio::test]
    async fn integration_sni_denies_domain_suffix_without_cache_binding() {
        let shared = SharedState::new(4); // empty cache
        let policy = NetworkPolicy {
            default_egress: Action::Deny,
            default_ingress: Action::Allow,
            rules: vec![Rule {
                direction: crate::policy::Direction::Egress,
                destination: Destination::DomainSuffix(".pythonhosted.org".parse().unwrap()),
                protocols: vec![Protocol::Tcp],
                ports: vec![PortRange::single(443)],
                action: Action::Allow,
            }],
        };
        let dst = SocketAddr::new(SHARED_FASTLY_IP.parse().unwrap(), 443);

        let (tx, mut rx) = mpsc::channel(4);
        tx.send(Bytes::from(synthetic_client_hello(
            "files.pythonhosted.org",
        )))
        .await
        .unwrap();
        drop(tx);

        let (_buf, sni) = peek_for_sni(&mut rx, PEEK_BUF_SIZE, PEEK_BUDGET).await;
        let source = sni
            .as_deref()
            .map(HostnameSource::Sni)
            .unwrap_or(HostnameSource::CacheOnly);
        let eval = policy.evaluate_egress_with_source(dst, Protocol::Tcp, &shared, source);
        assert_eq!(eval, EgressEvaluation::Deny);
    }
}

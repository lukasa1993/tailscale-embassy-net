//! Board-independent wiring for an Embassy application.
//!
//! A board crate should put every buffer below in `StaticCell`, seed independent
//! CSPRNG handles from its hardware RNG, and pass its authenticated wall-clock
//! type as `TlsClockType`.
//!
//! After [`connect_and_read_first_map`] and [`connect_selected_derp`] complete,
//! construct `TailnetRouter::from_map` and `new_tailnet_stack`, then spawn these
//! long-lived futures as distinct Embassy tasks:
//!
//! 1. the physical `embassy-net` runner;
//! 2. [`wait_for_map_change`] for the control connection;
//! 3. `run_derp_connection` for the DERP TLS connection;
//! 4. `run_tunnel_timer` for WireGuard timer ticks;
//! 5. `run_tailnet_tunnel` for routing, cryptokey validation, and the IP driver;
//! 6. the tailnet `embassy-net` runner;
//! 7. `run_http_server` for picoserve.
//!
//! The DERP/tunnel channels should be
//! `Channel<CriticalSectionRawMutex, PeerDatagram<WIREGUARD_BUFFER_SIZE>, 2>`;
//! the timer channel needs capacity one. A full map update ends the control
//! task and the board supervisor rebuilds the bounded peer router before
//! reconnecting. No task runs a second HTTP listener on the physical stack.

use embassy_net::Stack;
use rand_core::CryptoRngCore;
use tailscale_embassy_core::control::{ControlClient, ControlConfig, ControlMap, DerpNode};
use tailscale_embassy_core::derp::DerpClient;
use tailscale_embassy_core::{DiscoPrivateKey, Endpoint, KeySet, Rng, Storage, TcpTransport};
use tailscale_embassy_net::{EmbassyTcp, VerifiedTls, resolve_ipv4};

const CERT_SIZE: usize = tls_transport::DEFAULT_CERT_SIZE;

/// Control connection type retained by the firmware's long-lived task.
pub type EmbassyControl<'a, R, C> = ControlClient<VerifiedTls<'a, EmbassyTcp<'a>, R, C, CERT_SIZE>>;

/// DERP connection type retained beside the one-peer WireGuard tunnel.
pub type EmbassyDerp<'a, R, C> = DerpClient<'a, VerifiedTls<'a, EmbassyTcp<'a>, R, C, CERT_SIZE>>;

/// Failures collapsed for this board-independent example.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExampleError {
    /// Persistent identity or entropy failed.
    Identity,
    /// DNS/TCP/TLS setup failed.
    Transport,
    /// Registration or map protocol failed.
    Control,
    /// The auth key did not authorize the node.
    NotAuthorized,
    /// The supervisor must rebuild peer/tunnel state from a fresh full map.
    NetmapChanged,
}

/// Load the persistent identity, establish both verified TLS connections,
/// register with a runtime auth key, and return the live map connection.
///
/// Keep calling `client.next_map(map_json).await` in the owning Embassy task.
/// The first returned map provides the control-assigned local address, dynamic
/// peer identities/addresses, packet filter, and one public DERP node.
#[allow(clippy::too_many_arguments)]
pub async fn connect_and_read_first_map<
    'a,
    S,
    ProtocolRng,
    KeyTlsRng,
    ControlTlsRng,
    TlsClockType,
>(
    stack: Stack<'a>,
    storage: &mut S,
    protocol_rng: &mut ProtocolRng,
    key_tls_rng: KeyTlsRng,
    control_tls_rng: ControlTlsRng,
    endpoint: Endpoint,
    control_hostname: &'a str,
    device_hostname: &str,
    auth_key: &str,
    trust_anchor_der: &'a [u8],
    key_tcp_rx: &'a mut [u8],
    key_tcp_tx: &'a mut [u8],
    control_tcp_rx: &'a mut [u8],
    control_tcp_tx: &'a mut [u8],
    key_tls_rx: &'a mut [u8],
    key_tls_tx: &'a mut [u8],
    control_tls_rx: &'a mut [u8],
    control_tls_tx: &'a mut [u8],
    http_scratch: &mut [u8],
    response: &mut [u8],
    map_json: &mut [u8],
) -> Result<
    (
        KeySet,
        DiscoPrivateKey,
        EmbassyControl<'a, ControlTlsRng, TlsClockType>,
        ControlMap,
    ),
    ExampleError,
>
where
    S: Storage,
    ProtocolRng: Rng,
    KeyTlsRng: CryptoRngCore,
    ControlTlsRng: CryptoRngCore,
    TlsClockType: embedded_tls::TlsClock,
{
    let keys = KeySet::load_or_generate(storage, protocol_rng)
        .await
        .map_err(|_| ExampleError::Identity)?;
    let disco_key = DiscoPrivateKey::generate(protocol_rng).map_err(|_| ExampleError::Identity)?;

    let mut key_socket = EmbassyTcp::new(stack, key_tcp_rx, key_tcp_tx);
    TcpTransport::connect(&mut key_socket, endpoint)
        .await
        .map_err(|_| ExampleError::Transport)?;
    let key_tls = VerifiedTls::<_, _, TlsClockType, CERT_SIZE>::new(
        key_socket,
        endpoint,
        control_hostname,
        key_tls_rx,
        key_tls_tx,
        key_tls_rng,
        trust_anchor_der,
    )
    .map_err(|_| ExampleError::Transport)?;

    let mut control_socket = EmbassyTcp::new(stack, control_tcp_rx, control_tcp_tx);
    TcpTransport::connect(&mut control_socket, endpoint)
        .await
        .map_err(|_| ExampleError::Transport)?;
    let control_tls = VerifiedTls::<_, _, TlsClockType, CERT_SIZE>::new(
        control_socket,
        endpoint,
        control_hostname,
        control_tls_rx,
        control_tls_tx,
        control_tls_rng,
        trust_anchor_der,
    )
    .map_err(|_| ExampleError::Transport)?;

    let config = ControlConfig {
        hostname: control_hostname,
        endpoint,
        device_hostname,
        disco_key: &disco_key,
    };
    let mut client = ControlClient::connect(
        key_tls,
        control_tls,
        config,
        &keys,
        protocol_rng,
        http_scratch,
    )
    .await
    .map_err(|_| ExampleError::Control)?;
    let registration = client
        .register(auth_key, false, http_scratch, response)
        .await;
    // The only buffer that held a serialized auth key is wiped immediately,
    // on success or failure.
    http_scratch.fill(0);
    let registration = registration.map_err(|_| ExampleError::Control)?;
    if !registration.machine_authorized || registration.node_key_expired {
        return Err(ExampleError::NotAuthorized);
    }
    client
        .start_map(http_scratch)
        .await
        .map_err(|_| ExampleError::Control)?;
    let first_map = client
        .next_map(map_json)
        .await
        .map_err(|_| ExampleError::Control)?;
    Ok((keys, disco_key, client, first_map))
}

/// Keep the authenticated control map stream active in its own Embassy task.
///
/// This bounded first version deliberately asks the board supervisor to
/// reconnect and rebuild all peer state after the next map response instead of
/// trying to merge incremental control updates in place.
pub async fn wait_for_map_change<T: tailscale_embassy_core::TlsTransport>(
    client: &mut ControlClient<T>,
    map_json: &mut [u8],
) -> Result<(), ExampleError> {
    let result = client.next_map(map_json).await;
    map_json.fill(0);
    result.map_err(|_| ExampleError::Control)?;
    Err(ExampleError::NetmapChanged)
}

/// Connect the first selected public DERP node from the authenticated map.
/// The dedicated `run_derp_connection` task passes encrypted datagrams through
/// bounded channels to the separate `run_tailnet_tunnel` task.
#[allow(clippy::too_many_arguments)]
pub async fn connect_selected_derp<'a, ProtocolRng, TlsRng, TlsClockType>(
    stack: Stack<'a>,
    derp: &'a DerpNode,
    node_key: &tailscale_embassy_core::NodePrivateKey,
    protocol_rng: &mut ProtocolRng,
    tls_rng: TlsRng,
    trust_anchor_der: &'a [u8],
    tcp_rx: &'a mut [u8],
    tcp_tx: &'a mut [u8],
    tls_rx: &'a mut [u8],
    tls_tx: &'a mut [u8],
    http_scratch: &mut [u8],
    derp_frame: &'a mut [u8],
) -> Result<EmbassyDerp<'a, TlsRng, TlsClockType>, ExampleError>
where
    ProtocolRng: Rng,
    TlsRng: CryptoRngCore,
    TlsClockType: embedded_tls::TlsClock,
{
    let ipv4 = match derp.ipv4 {
        Some(address) => address,
        None => resolve_ipv4(stack, derp.hostname.as_str())
            .await
            .map_err(|_| ExampleError::Transport)?,
    };
    let endpoint = Endpoint::new(ipv4, derp.port);
    let mut socket = EmbassyTcp::new(stack, tcp_rx, tcp_tx);
    TcpTransport::connect(&mut socket, endpoint)
        .await
        .map_err(|_| ExampleError::Transport)?;
    let tls = VerifiedTls::<_, _, TlsClockType, CERT_SIZE>::new(
        socket,
        endpoint,
        derp.hostname.as_str(),
        tls_rx,
        tls_tx,
        tls_rng,
        trust_anchor_der,
    )
    .map_err(|_| ExampleError::Transport)?;
    DerpClient::connect(
        tls,
        endpoint,
        derp.hostname.as_str(),
        node_key.clone(),
        protocol_rng,
        http_scratch,
        derp_frame,
    )
    .await
    .map_err(|_| ExampleError::Control)
}

fn main() {
    // See this module's documentation: the concrete board owns the executor,
    // physical device, StaticCells, hardware entropy, task spawns, reconnect
    // supervisor, and authenticated clock.
}

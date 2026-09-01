//! IP-native Embassy stack and fixed-buffer tailnet HTTP service.

use core::cell::RefCell;
use core::net::Ipv4Addr;

use embassy_futures::select::{Either, Either4, select, select4};
use embassy_net::{Config, Ipv4Cidr, Stack, StackResources, StaticConfigV4};
use embassy_net_driver_channel::driver::{HardwareAddress, LinkState};
use embassy_net_driver_channel::{Device, Runner, State};
use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::channel::{Receiver, Sender};
use embassy_time::{Duration, Ticker, with_timeout};
use heapless::Vec;
use picoserve::io::Write as _;
use tailscale_embassy_core::control::ControlMap;
use tailscale_embassy_core::derp::{DerpClient, DerpError, DerpIncoming};
use tailscale_embassy_core::disco::{DiscoPing, DiscoSession, looks_like_disco};
use tailscale_embassy_core::packet::{PacketError, parse_ipv4};
use tailscale_embassy_core::tunnel::{RouterError, RouterInbound, TailnetRouter};
use tailscale_embassy_core::{
    Clock, DiscoPublicKey, Endpoint, NodePrivateKey, NodePublicKey, Rng, TlsTransport,
    TransportError, UdpTransport,
};

/// Tailscale's IPv4 CGNAT route length (`100.64.0.0/10`).
pub const TAILNET_PREFIX_LEN: u8 = 10;
/// Default inbound HTTP port.
pub const DEFAULT_HTTP_PORT: u16 = 80;
/// Recommended raw IPv4 MTU and per-packet driver buffer size.
pub const DEFAULT_TAILNET_MTU: usize = 1500;
/// Default number of raw packets queued toward the tailnet stack.
pub const DEFAULT_TAILNET_RX_PACKETS: usize = 2;
/// Default number of raw packets queued out of the tailnet stack.
pub const DEFAULT_TAILNET_TX_PACKETS: usize = 2;
/// Default socket-table slots: one listener plus stack bookkeeping headroom.
pub const DEFAULT_TAILNET_SOCKET_SLOTS: usize = 2;
/// Default picoserve request/header scratch bytes.
pub const DEFAULT_HTTP_BUFFER_SIZE: usize = 1024;
/// Default TCP receive bytes for the one HTTP connection.
pub const DEFAULT_HTTP_TCP_RX_SIZE: usize = 1024;
/// Default TCP transmit bytes for the one HTTP connection.
pub const DEFAULT_HTTP_TCP_TX_SIZE: usize = 1024;
/// Time after each received DERP packet for the tunnel and TCP stack to queue
/// immediate response traffic before the next non-cancellable TLS read.
pub const DEFAULT_DERP_REPLY_DRAIN: Duration = Duration::from_millis(25);
/// Maximum DERP sends before the task must service another inbound frame.
///
/// Strict alternation prevents a TCP retransmit producer from filling the
/// relay/TLS buffers with duplicate segments before the peer ACK is serviced.
pub const MAX_DERP_SEND_BURST: usize = 1;
/// Normal packet processing does not claim WireGuard denial-of-service load.
/// A future load sensor must set this deliberately rather than treating every
/// inbound handshake as cookie-challenge traffic.
const fn tunnel_under_load() -> bool {
    false
}

/// Caller-owned fixed packet storage used by the IP-native channel driver.
pub type TailnetDriverState<const MTU: usize, const RX: usize, const TX: usize> =
    State<MTU, RX, TX>;

/// The `embassy-net` runner for the IP-native tailnet stack.
pub type TailnetStackRunner<'d, const MTU: usize> = embassy_net::Runner<'d, Device<'d, MTU>>;

/// Lower side of the IP-native driver used by the encrypted tunnel task.
pub struct TailnetPacketIo<'d, const MTU: usize> {
    runner: Runner<'d, MTU>,
}

/// Fixed-buffer tailnet driver failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TailnetIoError {
    /// The caller's copy buffer or driver MTU was too small.
    BufferTooSmall,
    /// A malformed, spoofable, or unsupported IPv4 packet was rejected.
    Packet(PacketError),
}

impl From<PacketError> for TailnetIoError {
    fn from(error: PacketError) -> Self {
        Self::Packet(error)
    }
}

/// Create a statically addressed, IP-native tailnet stack.
///
/// The local address comes from the authenticated netmap. Giving it the `/10`
/// prefix installs the on-link route for Tailscale IPv4 peers without a fake
/// gateway or Ethernet/ARP layer.
pub fn new_tailnet_stack<
    'd,
    const MTU: usize,
    const RX: usize,
    const TX: usize,
    const SOCK: usize,
>(
    state: &'d mut TailnetDriverState<MTU, RX, TX>,
    resources: &'d mut StackResources<SOCK>,
    local_address: Ipv4Addr,
    random_seed: u64,
) -> (
    Stack<'d>,
    TailnetStackRunner<'d, MTU>,
    TailnetPacketIo<'d, MTU>,
) {
    let (mut packet_runner, device) = embassy_net_driver_channel::new(state, HardwareAddress::Ip);
    packet_runner.set_link_state(LinkState::Up);
    let config = Config::ipv4_static(StaticConfigV4 {
        address: Ipv4Cidr::new(local_address, TAILNET_PREFIX_LEN),
        gateway: None,
        dns_servers: Default::default(),
    });
    let (stack, stack_runner) = embassy_net::new(device, config, resources, random_seed);
    (
        stack,
        stack_runner,
        TailnetPacketIo {
            runner: packet_runner,
        },
    )
}

impl<const MTU: usize> TailnetPacketIo<'_, MTU> {
    /// Copy the next raw IPv4 packet emitted by `embassy-net` into caller storage.
    pub async fn receive_outbound(&mut self, out: &mut [u8]) -> Result<usize, TailnetIoError> {
        let packet = self.runner.tx_buf().await;
        let result = if packet.len() > out.len() {
            Err(TailnetIoError::BufferTooSmall)
        } else {
            out[..packet.len()].copy_from_slice(packet);
            Ok(packet.len())
        };
        self.runner.tx_done();
        result
    }

    /// Inject authenticated raw IPv4 into `embassy-net`'s receive queue.
    pub async fn inject_ipv4(&mut self, packet: &[u8]) -> Result<(), TailnetIoError> {
        let packet = parse_ipv4(packet)?.bytes;
        if packet.len() > MTU {
            return Err(TailnetIoError::BufferTooSmall);
        }
        let buffer = self.runner.rx_buf().await;
        buffer[..packet.len()].copy_from_slice(packet);
        self.runner.rx_done(packet.len());
        Ok(())
    }
}

/// One fixed-capacity WireGuard datagram passed between the tunnel and DERP
/// Embassy tasks.
#[derive(Clone, Eq, PartialEq)]
pub struct PeerDatagram<const SIZE: usize> {
    peer: NodePublicKey,
    len: usize,
    bytes: [u8; SIZE],
}

/// One WireGuard datagram routed to an authenticated direct UDP endpoint.
#[derive(Clone, Eq, PartialEq)]
pub struct DirectDatagram<const SIZE: usize> {
    endpoint: Endpoint,
    packet: PeerDatagram<SIZE>,
}

impl<const SIZE: usize> DirectDatagram<SIZE> {
    /// Copy a complete peer datagram and its validated UDP destination.
    pub fn new(peer: NodePublicKey, endpoint: Endpoint, datagram: &[u8]) -> Option<Self> {
        Some(Self {
            endpoint,
            packet: PeerDatagram::new(peer, datagram)?,
        })
    }

    /// Validated direct UDP destination.
    pub const fn endpoint(&self) -> Endpoint {
        self.endpoint
    }

    /// Intended peer node key.
    pub const fn peer(&self) -> NodePublicKey {
        self.packet.peer()
    }

    /// WireGuard datagram without channel padding.
    pub fn datagram(&self) -> &[u8] {
        self.packet.datagram()
    }
}

impl<const SIZE: usize> core::fmt::Debug for DirectDatagram<SIZE> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DirectDatagram")
            .field("endpoint", &self.endpoint)
            .field("peer", &self.peer())
            .field("len", &self.datagram().len())
            .finish()
    }
}

impl<const SIZE: usize> PeerDatagram<SIZE> {
    /// Copy a complete datagram into task-owned channel storage.
    pub fn new(peer: NodePublicKey, datagram: &[u8]) -> Option<Self> {
        if datagram.len() > SIZE {
            return None;
        }
        let mut bytes = [0; SIZE];
        bytes[..datagram.len()].copy_from_slice(datagram);
        Some(Self {
            peer,
            len: datagram.len(),
            bytes,
        })
    }

    /// Authenticated or intended peer node key.
    pub const fn peer(&self) -> NodePublicKey {
        self.peer
    }

    /// WireGuard datagram without channel padding.
    pub fn datagram(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl<const SIZE: usize> core::fmt::Debug for PeerDatagram<SIZE> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PeerDatagram")
            .field("peer", &self.peer)
            .field("len", &self.len)
            .finish()
    }
}

/// Fatal reason for reconnecting the dedicated DERP task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DerpTaskError {
    /// DERP framing or its verified TLS transport failed.
    Derp(DerpError),
    /// The relay asked clients to reconnect elsewhere.
    Restarting,
}

impl From<DerpError> for DerpTaskError {
    fn from(error: DerpError) -> Self {
        Self::Derp(error)
    }
}

/// Authentication data required for one peer's DERP-routed disco packets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DerpPeer {
    node_key: NodePublicKey,
    disco_key: Option<DiscoPublicKey>,
    direct_endpoint: Option<Endpoint>,
}

/// Compact, immutable projection of an authenticated control map for DERP.
///
/// Keeping this separate from the mutable control map avoids retaining a full
/// second copy of its packet filter. Capacity failure is explicit so firmware
/// can fail closed rather than silently omit an authenticated peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerpPeerMap<const MAX: usize> {
    region_id: u16,
    peers: Vec<DerpPeer, MAX>,
}

impl<const MAX: usize> DerpPeerMap<MAX> {
    /// Project every peer from `map`, or return `None` if `MAX` is too small.
    pub fn from_control_map(map: &ControlMap) -> Option<Self> {
        let mut peers = Vec::new();
        for peer in &map.peers {
            peers
                .push(DerpPeer {
                    node_key: peer.key,
                    disco_key: peer.disco_key,
                    direct_endpoint: None,
                })
                .ok()?;
        }
        Some(Self {
            region_id: map.derp.region_id,
            peers,
        })
    }

    fn disco_key_for(&self, node_key: NodePublicKey) -> Option<DiscoPublicKey> {
        self.peers
            .iter()
            .find(|peer| peer.node_key == node_key)
            .and_then(|peer| peer.disco_key)
    }

    fn authenticate_direct_ping(
        &mut self,
        source: DiscoPublicKey,
        claimed_node: Option<NodePublicKey>,
        endpoint: Endpoint,
    ) -> Option<NodePublicKey> {
        if endpoint.port == 0 {
            return None;
        }
        let peer = self
            .peers
            .iter_mut()
            .find(|peer| peer.disco_key == Some(source))?;
        if claimed_node.is_some_and(|claimed| claimed != peer.node_key) {
            return None;
        }
        peer.direct_endpoint = Some(endpoint);
        Some(peer.node_key)
    }

    fn peer_for_direct_endpoint(&self, endpoint: Endpoint) -> Option<NodePublicKey> {
        self.peers
            .iter()
            .find(|peer| peer.direct_endpoint == Some(endpoint))
            .map(|peer| peer.node_key)
    }

    fn direct_endpoint_for(&self, node_key: NodePublicKey) -> Option<Endpoint> {
        self.peers
            .iter()
            .find(|peer| peer.node_key == node_key)
            .and_then(|peer| peer.direct_endpoint)
    }
}

/// Authenticated routing and DERP-discovery state shared by the control,
/// tunnel, and relay tasks.
///
/// Callers normally place this value behind [`SharedTailnetState`]. A complete
/// candidate router and DERP projection are validated before either live value
/// is replaced, so readers never observe a partially applied control update.
pub struct TailnetControlState<const MAX: usize> {
    router: TailnetRouter<MAX>,
    derp_peers: DerpPeerMap<MAX>,
}

/// A zero-allocation critical-section wrapper for live authenticated state.
pub type SharedTailnetState<M, const MAX: usize> = Mutex<M, RefCell<TailnetControlState<MAX>>>;

/// Rejection reason for an authenticated live-map update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TailnetStateError {
    /// The cryptokey router rejected the new routes or policy.
    Router(RouterError),
    /// The peer projection exceeded its checked fixed capacity.
    PeerCapacity,
    /// Control selected another relay; the existing TLS relay must reconnect.
    DerpRegionChanged,
}

impl From<RouterError> for TailnetStateError {
    fn from(error: RouterError) -> Self {
        Self::Router(error)
    }
}

impl<const MAX: usize> TailnetControlState<MAX> {
    /// Build the initial shared state from one authenticated control map.
    pub fn from_control_map(
        local_key: &NodePrivateKey,
        map: &ControlMap,
    ) -> Result<Self, TailnetStateError> {
        Ok(Self {
            router: TailnetRouter::from_map(local_key, map)?,
            derp_peers: DerpPeerMap::from_control_map(map)
                .ok_or(TailnetStateError::PeerCapacity)?,
        })
    }

    /// Atomically replace live peer routes, discovery keys, and packet policy.
    ///
    /// A local-address or home-DERP change requires rebuilding infrastructure
    /// outside this state object and is rejected instead of applying an unsafe
    /// partial update.
    // Keep both bounded routing candidates in this callee's phase. Firmware
    // callers decode a bounded RawMap immediately before applying the state;
    // LTO must not merge those two large stack frames on constrained targets.
    #[inline(never)]
    pub fn apply_control_map(&mut self, map: &ControlMap) -> Result<(), TailnetStateError> {
        let mut derp_peers =
            DerpPeerMap::from_control_map(map).ok_or(TailnetStateError::PeerCapacity)?;
        if derp_peers.region_id != self.derp_peers.region_id {
            return Err(TailnetStateError::DerpRegionChanged);
        }
        self.router.refresh_from_map(map)?;
        retain_authenticated_endpoints(&self.derp_peers, &mut derp_peers);
        self.derp_peers = derp_peers;
        Ok(())
    }
}

fn retain_authenticated_endpoints<const MAX: usize>(
    current: &DerpPeerMap<MAX>,
    refreshed: &mut DerpPeerMap<MAX>,
) {
    for refreshed_peer in &mut refreshed.peers {
        if let Some(current_peer) = current.peers.iter().find(|current_peer| {
            current_peer.node_key == refreshed_peer.node_key
                && current_peer.disco_key == refreshed_peer.disco_key
        }) {
            refreshed_peer.direct_endpoint = current_peer.direct_endpoint;
        }
    }
}

/// Fatal failure of the direct UDP socket task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectTaskError {
    /// The bound Embassy UDP transport failed.
    Transport(TransportError),
}

impl From<TransportError> for DirectTaskError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

/// Own one already-bound UDP socket for encrypted disco and WireGuard traffic.
///
/// A peer endpoint becomes usable only after an authenticated disco Ping from
/// the peer's control-plane disco key. Non-disco WireGuard packets are then
/// accepted only from that exact observed endpoint.
#[allow(clippy::too_many_arguments)]
pub async fn run_direct_udp<
    M: RawMutex,
    StateMutex: RawMutex,
    U: UdpTransport,
    ProtocolRng: Rng,
    const DATAGRAM: usize,
    const QUEUE: usize,
    const MAX_PEERS: usize,
>(
    socket: &mut U,
    disco: &DiscoSession,
    state: &SharedTailnetState<StateMutex, MAX_PEERS>,
    rng: &mut ProtocolRng,
    from_tunnel: Receiver<'_, M, DirectDatagram<DATAGRAM>, QUEUE>,
    to_tunnel: Sender<'_, M, PeerDatagram<DATAGRAM>, QUEUE>,
    receive_buffer: &mut [u8],
    disco_reply: &mut [u8],
) -> Result<(), DirectTaskError> {
    loop {
        match select(socket.recv_from(receive_buffer), from_tunnel.receive()).await {
            Either::First(received) => {
                let (length, source) = received?;
                if looks_like_disco(&receive_buffer[..length]) {
                    let Ok(ping) = disco.receive_ping(&receive_buffer[..length]) else {
                        continue;
                    };
                    let peer = state.lock(|state| {
                        state.borrow_mut().derp_peers.authenticate_direct_ping(
                            ping.source,
                            ping.node_key,
                            source,
                        )
                    });
                    let Some(_peer) = peer else {
                        continue;
                    };
                    let Ok(pong) =
                        disco.build_pong(ping.source, ping.tx_id, source, rng, disco_reply)
                    else {
                        continue;
                    };
                    socket.send_to(source, pong).await?;
                    continue;
                }

                let peer =
                    state.lock(|state| state.borrow().derp_peers.peer_for_direct_endpoint(source));
                let Some(peer) = peer else {
                    continue;
                };
                let Some(packet) = PeerDatagram::new(peer, &receive_buffer[..length]) else {
                    continue;
                };
                // This task also consumes replies from the tunnel. Waiting on
                // a full inbound channel can deadlock with the tunnel waiting
                // on a full outbound channel. WireGuard retransmits dropped
                // datagrams, so bounded backpressure is deliberately lossy.
                let _ = to_tunnel.try_send(packet);
            }
            Either::Second(outbound) => {
                socket
                    .send_to(outbound.endpoint(), outbound.datagram())
                    .await?;
            }
        }
    }
}

enum TunnelAction<const DATAGRAM: usize> {
    None,
    InjectIpv4(usize),
    Send(PeerDatagram<DATAGRAM>),
}

/// Own the verified DERP connection as a task separate from packet routing.
///
/// A verified embedded-TLS operation is never cancelled: the task drains
/// already-produced tunnel output, awaits one complete DERP event, forwards
/// it, and briefly drains immediate tunnel/TCP replies before reading again.
/// This ordering covers inbound TCP response traffic without poisoning the TLS
/// state. Both channels are bounded and copy at most `DATAGRAM` bytes; no
/// per-packet allocation occurs.
#[allow(clippy::too_many_arguments)]
pub async fn run_derp_connection<
    M: RawMutex,
    StateMutex: RawMutex,
    T: TlsTransport,
    ProtocolRng: Rng,
    const DATAGRAM: usize,
    const QUEUE: usize,
    const MAX_PEERS: usize,
>(
    client: &mut DerpClient<'_, T>,
    disco: &DiscoSession,
    state: &SharedTailnetState<StateMutex, MAX_PEERS>,
    rng: &mut ProtocolRng,
    from_tunnel: Receiver<'_, M, PeerDatagram<DATAGRAM>, QUEUE>,
    to_tunnel: Sender<'_, M, PeerDatagram<DATAGRAM>, QUEUE>,
    receive_buffer: &mut [u8],
    disco_reply: &mut [u8],
) -> Result<(), DerpTaskError> {
    loop {
        for _ in 0..MAX_DERP_SEND_BURST {
            let Ok(outbound) = from_tunnel.try_receive() else {
                break;
            };
            client.send(outbound.peer(), outbound.datagram()).await?;
        }

        match client.receive(receive_buffer).await? {
            DerpIncoming::Packet { source, len } => {
                if looks_like_disco(&receive_buffer[..len]) {
                    let (peer_disco_key, region_id) = state.lock(|state| {
                        let state = state.borrow();
                        (
                            state.derp_peers.disco_key_for(source),
                            state.derp_peers.region_id,
                        )
                    });
                    let Some(peer_disco_key) = peer_disco_key else {
                        continue;
                    };
                    let Ok(ping) = disco.receive_ping(&receive_buffer[..len]) else {
                        continue;
                    };
                    if !derp_ping_matches_peer(peer_disco_key, ping, source) {
                        continue;
                    }
                    let Ok(pong) =
                        disco.build_derp_pong(ping.source, ping.tx_id, region_id, rng, disco_reply)
                    else {
                        continue;
                    };
                    client.send(source, pong).await?;
                    continue;
                }
                let packet = PeerDatagram::new(source, &receive_buffer[..len])
                    .ok_or(DerpTaskError::Derp(DerpError::Length))?;
                // Keep the DERP reader live even when the tunnel is briefly
                // saturated. Stalling here eventually fills the relay TCP
                // receive window and makes the server remove this client.
                let _ = to_tunnel.try_send(packet);
                // The tunnel task may emit a WireGuard handshake reply or
                // inject TCP whose stack response arrives a few polls later.
                if let Ok(outbound) =
                    with_timeout(DEFAULT_DERP_REPLY_DRAIN, from_tunnel.receive()).await
                {
                    client.send(outbound.peer(), outbound.datagram()).await?;
                }
            }
            DerpIncoming::PeerGone(_) => {}
            DerpIncoming::Restarting { .. } => return Err(DerpTaskError::Restarting),
            DerpIncoming::Activity | DerpIncoming::Health { .. } => {}
        }
    }
}

fn derp_ping_matches_peer(
    expected_disco_key: DiscoPublicKey,
    ping: DiscoPing,
    source_peer: NodePublicKey,
) -> bool {
    expected_disco_key == ping.source && ping.node_key.is_none_or(|claimed| claimed == source_peer)
}

/// Periodically wake WireGuard timer processing without busy-polling.
pub async fn run_tunnel_timer<M: RawMutex, const QUEUE: usize>(
    to_tunnel: Sender<'_, M, (), QUEUE>,
    interval_millis: u64,
) -> ! {
    let mut ticker = Ticker::every(Duration::from_millis(interval_millis));
    loop {
        ticker.next().await;
        // Timer events coalesce while the tunnel task is busy.
        let _ = to_tunnel.try_send(());
    }
}

/// Own peer lookup, WireGuard state, source/policy validation, and the lower
/// side of the IP-native driver as one allocation-free Embassy task.
///
/// Invalid, spoofed, unauthorized, unknown-peer, and malformed packets are
/// deliberately dropped. The dedicated control task supplies a fresh router
/// after a full netmap update or reconnect.
fn dispatch_underlay<
    M: RawMutex,
    StateMutex: RawMutex,
    const PEERS: usize,
    const DATAGRAM: usize,
    const QUEUE: usize,
>(
    state: &SharedTailnetState<StateMutex, PEERS>,
    packet: PeerDatagram<DATAGRAM>,
    to_derp: &Sender<'_, M, PeerDatagram<DATAGRAM>, QUEUE>,
    to_direct: &Sender<'_, M, DirectDatagram<DATAGRAM>, QUEUE>,
) {
    let endpoint = state.lock(|state| state.borrow().derp_peers.direct_endpoint_for(packet.peer()));
    let Some(endpoint) = endpoint else {
        let _ = to_derp.try_send(packet);
        return;
    };
    let Some(direct) = DirectDatagram::new(packet.peer(), endpoint, packet.datagram()) else {
        let _ = to_derp.try_send(packet);
        return;
    };
    // Both underlays are datagram transports with their own retry machinery.
    // Never let a full capacity-one queue stop the tunnel from consuming the
    // opposite direction and create a two-task backpressure cycle.
    let _ = to_direct.try_send(direct);
    let _ = to_derp.try_send(packet);
}

fn process_incoming<
    StateMutex: RawMutex,
    C: Clock,
    Random: Rng,
    const PEERS: usize,
    const DATAGRAM: usize,
>(
    state: &SharedTailnetState<StateMutex, PEERS>,
    clock: &C,
    rng: &mut Random,
    incoming: PeerDatagram<DATAGRAM>,
    wireguard: &mut [u8],
) -> TunnelAction<DATAGRAM> {
    state.lock(|state| {
        let mut state = state.borrow_mut();
        match state.router.receive_derp(
            clock,
            rng,
            incoming.peer(),
            tunnel_under_load(),
            incoming.datagram(),
            wireguard,
        ) {
            Ok(RouterInbound::Ipv4(packet)) => TunnelAction::InjectIpv4(packet.bytes.len()),
            Ok(RouterInbound::Reply(outbound)) => {
                PeerDatagram::new(outbound.destination, outbound.datagram)
                    .map_or(TunnelAction::None, TunnelAction::Send)
            }
            Ok(RouterInbound::HandshakeComplete(peer)) => state
                .router
                .flush_pending(clock, rng, peer, wireguard)
                .ok()
                .flatten()
                .and_then(|outbound| PeerDatagram::new(outbound.destination, outbound.datagram))
                .map_or(TunnelAction::None, TunnelAction::Send),
            Ok(RouterInbound::Idle) => TunnelAction::None,
            Err(_error) => {
                #[cfg(feature = "defmt")]
                defmt::warn!(
                    "tailnet inbound underlay datagram dropped: {:?}",
                    defmt::Debug2Format(&_error)
                );
                TunnelAction::None
            }
        }
    })
}

#[allow(clippy::too_many_arguments)]
pub async fn run_tailnet_tunnel<
    M: RawMutex,
    StateMutex: RawMutex,
    C: Clock,
    Random: Rng,
    const MTU: usize,
    const PEERS: usize,
    const DATAGRAM: usize,
    const QUEUE: usize,
    const TIMER_QUEUE: usize,
>(
    mut packet_io: TailnetPacketIo<'_, MTU>,
    state: &SharedTailnetState<StateMutex, PEERS>,
    clock: &C,
    rng: &mut Random,
    to_derp: Sender<'_, M, PeerDatagram<DATAGRAM>, QUEUE>,
    from_derp: Receiver<'_, M, PeerDatagram<DATAGRAM>, QUEUE>,
    to_direct: Sender<'_, M, DirectDatagram<DATAGRAM>, QUEUE>,
    from_direct: Receiver<'_, M, PeerDatagram<DATAGRAM>, QUEUE>,
    timer_ticks: Receiver<'_, M, (), TIMER_QUEUE>,
    raw_ipv4: &mut [u8],
    wireguard: &mut [u8],
) -> ! {
    loop {
        match select4(
            packet_io.receive_outbound(raw_ipv4),
            from_derp.receive(),
            from_direct.receive(),
            timer_ticks.receive(),
        )
        .await
        {
            Either4::First(Ok(length)) => {
                let outbound = state.lock(|state| {
                    let mut state = state.borrow_mut();
                    state
                        .router
                        .send_ipv4(clock, rng, &raw_ipv4[..length], wireguard)
                });
                match outbound {
                    Ok(outbound) => {
                        if let Some(packet) =
                            PeerDatagram::new(outbound.destination, outbound.datagram)
                        {
                            dispatch_underlay(state, packet, &to_derp, &to_direct);
                        }
                    }
                    Err(_error) => {
                        #[cfg(feature = "defmt")]
                        defmt::warn!(
                            "tailnet outbound IPv4 dropped: {:?}",
                            defmt::Debug2Format(&_error)
                        );
                    }
                }
            }
            Either4::First(Err(_)) => {}
            Either4::Second(incoming) | Either4::Third(incoming) => {
                let action = process_incoming(state, clock, rng, incoming, wireguard);
                match action {
                    TunnelAction::InjectIpv4(length) => {
                        if packet_io.inject_ipv4(&wireguard[..length]).await.is_err() {
                            #[cfg(feature = "defmt")]
                            defmt::warn!("tailnet IPv4 injection dropped");
                        }
                    }
                    TunnelAction::Send(packet) => {
                        dispatch_underlay(state, packet, &to_derp, &to_direct)
                    }
                    TunnelAction::None => {}
                }
            }
            Either4::Fourth(()) => {
                let outbound = state.lock(|state| {
                    let mut state = state.borrow_mut();
                    state.router.poll_next(clock, rng, wireguard)
                });
                match outbound {
                    Ok(Some(outbound)) => {
                        if let Some(packet) =
                            PeerDatagram::new(outbound.destination, outbound.datagram)
                        {
                            dispatch_underlay(state, packet, &to_derp, &to_direct);
                        }
                    }
                    Ok(None) => {}
                    Err(_error) => {
                        #[cfg(feature = "defmt")]
                        defmt::warn!(
                            "tailnet WireGuard timer dropped: {:?}",
                            defmt::Debug2Format(&_error)
                        );
                    }
                }
            }
        }
    }
}

/// Construct the two fixed HTTP routes.
pub fn http_router() -> picoserve::Router<impl picoserve::routing::PathRouter> {
    use picoserve::routing::get;

    picoserve::Router::new()
        .route(
            "/health",
            get(|| async { StaticContent::new("application/json", "{\"ok\":true}") }),
        )
        .route(
            "/",
            get(|| async { StaticContent::new("text/plain", "Embassy on Tailscale") }),
        )
}

#[derive(Clone, Copy)]
struct StaticContent {
    content_type: &'static str,
    body: &'static str,
}

impl StaticContent {
    const fn new(content_type: &'static str, body: &'static str) -> Self {
        Self { content_type, body }
    }
}

impl picoserve::response::Content for StaticContent {
    fn content_type(&self) -> &'static str {
        self.content_type
    }

    fn content_length(&self) -> usize {
        self.body.len()
    }

    async fn write_content<W: picoserve::io::Write>(self, mut writer: W) -> Result<(), W::Error> {
        writer.write_all(self.body.as_bytes()).await
    }
}

/// Conservative fixed timeouts for a single concurrent connection.
pub const fn http_config() -> picoserve::Config {
    picoserve::Config::new(picoserve::Timeouts {
        start_read_request: Duration::from_secs(10),
        persistent_start_read_request: Duration::from_secs(1),
        read_request: Duration::from_secs(5),
        write: Duration::from_secs(5),
    })
    .close_connection_after_response()
}

/// Run one allocation-free picoserve listener on the tailnet stack only.
///
/// Spawn this future once to cap HTTP concurrency at one. All request, TCP RX,
/// and TCP TX storage is caller-owned and should normally live in `StaticCell`.
pub async fn run_http_server(
    stack: Stack<'_>,
    port: u16,
    http_buffer: &mut [u8],
    tcp_rx_buffer: &mut [u8],
    tcp_tx_buffer: &mut [u8],
) -> ! {
    let app = http_router();
    let config = http_config();
    loop {
        let mut socket = embassy_net::tcp::TcpSocket::new(stack, tcp_rx_buffer, tcp_tx_buffer);
        if socket.accept(port).await.is_err() {
            socket.abort();
            continue;
        }
        socket.set_keep_alive(Some(Duration::from_secs(30)));
        socket.set_timeout(Some(Duration::from_secs(45)));
        let _ = picoserve::Server::new(&app, &config, http_buffer)
            .serve(ReasonPhraseSocket(socket))
            .await;
    }
}

/// picoserve intentionally emits an empty HTTP/1.1 reason phrase. Preserve its
/// Embassy server machinery while supplying the exact required `200 OK` line.
struct ReasonPhraseSocket<'a>(embassy_net::tcp::TcpSocket<'a>);

struct ReasonPhraseWriter<'a> {
    inner: embassy_net::tcp::TcpWriter<'a>,
    first_line: [u8; 32],
    first_line_len: usize,
    first_line_written: bool,
}

impl picoserve::io::ErrorType for ReasonPhraseWriter<'_> {
    type Error = embassy_net::tcp::Error;
}

impl picoserve::io::Write for ReasonPhraseWriter<'_> {
    async fn write(&mut self, bytes: &[u8]) -> Result<usize, Self::Error> {
        if self.first_line_written {
            return self.inner.write(bytes).await;
        }

        let mut consumed = 0;
        while capture_first_line_byte(
            consumed,
            bytes.len(),
            self.first_line_len,
            self.first_line.len(),
        ) {
            self.first_line[self.first_line_len] = bytes[consumed];
            self.first_line_len += 1;
            consumed += 1;
            if self.first_line[..self.first_line_len].ends_with(b"\r\n") {
                return self.finish_first_line(bytes, consumed).await;
            }
        }

        if first_line_is_full(self.first_line_len, self.first_line.len()) {
            return self.finish_first_line(bytes, consumed).await;
        }
        Ok(bytes.len())
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        if should_flush_first_line(self.first_line_written, self.first_line_len) {
            self.write_first_line().await?;
        }
        self.inner.flush().await
    }
}

fn capture_first_line_byte(
    consumed: usize,
    input_len: usize,
    first_line_len: usize,
    first_line_capacity: usize,
) -> bool {
    consumed < input_len && first_line_len < first_line_capacity
}

fn has_unwritten_bytes(consumed: usize, input_len: usize) -> bool {
    consumed < input_len
}

fn first_line_is_full(first_line_len: usize, first_line_capacity: usize) -> bool {
    first_line_len == first_line_capacity
}

fn should_flush_first_line(first_line_written: bool, first_line_len: usize) -> bool {
    !first_line_written && first_line_len != 0
}

impl ReasonPhraseWriter<'_> {
    async fn finish_first_line(
        &mut self,
        bytes: &[u8],
        consumed: usize,
    ) -> Result<usize, embassy_net::tcp::Error> {
        self.write_first_line().await?;
        if has_unwritten_bytes(consumed, bytes.len()) {
            self.inner.write_all(&bytes[consumed..]).await?;
        }
        Ok(bytes.len())
    }

    async fn write_first_line(&mut self) -> Result<(), embassy_net::tcp::Error> {
        const PICOSERVE_OK: &[u8] = b"HTTP/1.1 200 \r\n";
        const REQUIRED_OK: &[u8] = b"HTTP/1.1 200 OK\r\n";
        if &self.first_line[..self.first_line_len] == PICOSERVE_OK {
            self.inner.write_all(REQUIRED_OK).await?;
        } else {
            self.inner
                .write_all(&self.first_line[..self.first_line_len])
                .await?;
        }
        self.first_line_written = true;
        Ok(())
    }
}

impl<'s> picoserve::io::Socket<picoserve::EmbassyRuntime> for ReasonPhraseSocket<'s> {
    type Error = embassy_net::tcp::Error;
    type ReadHalf<'a>
        = embassy_net::tcp::TcpReader<'a>
    where
        's: 'a;
    type WriteHalf<'a>
        = ReasonPhraseWriter<'a>
    where
        's: 'a;

    fn split(&mut self) -> (Self::ReadHalf<'_>, Self::WriteHalf<'_>) {
        let (reader, writer) = self.0.split();
        (
            reader,
            ReasonPhraseWriter {
                inner: writer,
                first_line: [0; 32],
                first_line_len: 0,
                first_line_written: false,
            },
        )
    }

    async fn abort<T: picoserve::Timer<picoserve::EmbassyRuntime>>(
        self,
        timeouts: &picoserve::Timeouts,
        timer: &mut T,
    ) -> Result<(), picoserve::Error<Self::Error>> {
        picoserve::io::Socket::abort(self.0, timeouts, timer).await
    }

    async fn shutdown<T: picoserve::Timer<picoserve::EmbassyRuntime>>(
        self,
        timeouts: &picoserve::Timeouts,
        timer: &mut T,
    ) -> Result<(), picoserve::Error<Self::Error>> {
        // This server handles exactly one request per connection. Waiting for
        // the peer's FIN keeps our only socket slot out of LISTEN and drops
        // subsequent SYNs over a high-latency DERP path. `ContentBody` has
        // already flushed and received ACKs for the complete declared body, so
        // send an immediate RST and recycle the listener. TCP flush only waits
        // for the RST to leave the local IP stack, not for a peer round trip.
        picoserve::io::Socket::abort(self.0, timeouts, timer).await
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "host-tests")]
    use core::cell::Cell;

    #[cfg(feature = "host-tests")]
    use embassy_futures::select::{Either, Either4, select, select4};
    #[cfg(not(feature = "host-tests"))]
    use embassy_net::StackResources;
    #[cfg(feature = "host-tests")]
    use embassy_net::{IpEndpoint, StackResources, tcp::TcpSocket};
    use embassy_sync::blocking_mutex::raw::NoopRawMutex;
    use embassy_sync::channel::Channel;

    use super::*;

    #[cfg(feature = "host-tests")]
    const TEST_MTU: usize = 1500;

    #[test]
    fn default_static_ram_budget_is_bounded() {
        assert!(!tunnel_under_load());
        let driver = size_of::<
            TailnetDriverState<
                DEFAULT_TAILNET_MTU,
                DEFAULT_TAILNET_RX_PACKETS,
                DEFAULT_TAILNET_TX_PACKETS,
            >,
        >();
        let sockets = size_of::<StackResources<DEFAULT_TAILNET_SOCKET_SLOTS>>();
        let control_state =
            size_of::<TailnetControlState<{ tailscale_embassy_core::control::MAX_PEERS }>>();
        let derp_channels = 2
            * DEFAULT_TAILNET_RX_PACKETS
            * size_of::<PeerDatagram<{ tailscale_embassy_core::tunnel::WIREGUARD_BUFFER_SIZE }>>();
        let http = DEFAULT_HTTP_BUFFER_SIZE + DEFAULT_HTTP_TCP_RX_SIZE + DEFAULT_HTTP_TCP_TX_SIZE;
        let scratch =
            DEFAULT_TAILNET_MTU + 2 * tailscale_embassy_core::tunnel::WIREGUARD_BUFFER_SIZE;
        std::println!(
            "driver={driver} sockets={sockets} control_state={control_state} derp_channels={derp_channels} http={http} scratch={scratch}"
        );
        assert!(driver <= 7 * 1024);
        assert!(sockets <= 4 * 1024);
        assert!(control_state <= 128 * 1024);
        assert!(derp_channels <= 9 * 1024);
        assert_eq!(http, 3 * 1024);
        assert!(scratch <= 6 * 1024);
    }

    #[test]
    fn static_route_contents_are_exact() {
        let health = StaticContent::new("application/json", "{\"ok\":true}");
        assert_eq!(health.content_type, "application/json");
        assert_eq!(health.body, "{\"ok\":true}");

        let root = StaticContent::new("text/plain", "Embassy on Tailscale");
        assert_eq!(root.content_type, "text/plain");
        assert_eq!(root.body, "Embassy on Tailscale");
    }

    #[test]
    fn derp_peer_projection_is_complete_or_fails_closed() {
        const NODE: &str =
            "nodekey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        const DISCO: &str =
            "discokey:404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
        let map = tailscale_embassy_core::control::parse_map_response(
            br#"{"Node":{"Addresses":["100.64.1.2/32"],"HomeDERP":1},"Peers":[{"ID":1,"Key":"nodekey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","DiscoKey":"discokey:404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","Addresses":["100.100.2.3/32"]}],"DERPMap":{"Regions":{"1":{"RegionID":1,"Nodes":[{"HostName":"derp1.example"}]}}}}"#,
        )
        .unwrap();

        let mut projected = DerpPeerMap::<1>::from_control_map(&map).unwrap();
        let node = NodePublicKey::parse(NODE).unwrap();
        let disco = DiscoPublicKey::parse(DISCO).unwrap();
        assert_eq!(projected.disco_key_for(node), Some(disco));
        let endpoint = Endpoint::new(Ipv4Addr::new(192, 168, 1, 9), 41641);
        assert_eq!(
            projected.authenticate_direct_ping(disco, Some(node), endpoint),
            Some(node)
        );
        assert_eq!(projected.peer_for_direct_endpoint(endpoint), Some(node));
        assert_eq!(projected.direct_endpoint_for(node), Some(endpoint));
        assert_eq!(
            projected.authenticate_direct_ping(
                disco,
                Some(NodePublicKey::from_bytes([9; 32])),
                Endpoint::new(Ipv4Addr::new(192, 168, 1, 10), 41641),
            ),
            None
        );
        assert_eq!(projected.direct_endpoint_for(node), Some(endpoint));
        assert!(DerpPeerMap::<0>::from_control_map(&map).is_none());
    }

    #[test]
    fn peer_datagram_accepts_exact_capacity_and_rejects_one_byte_more() {
        let peer = NodePublicKey::from_bytes([3; 32]);
        let exact = PeerDatagram::<4>::new(peer, &[1, 2, 3, 4]).unwrap();
        assert_eq!(exact.peer(), peer);
        assert_eq!(exact.datagram(), &[1, 2, 3, 4]);
        assert!(PeerDatagram::<4>::new(peer, &[1, 2, 3, 4, 5]).is_none());
    }

    #[test]
    fn full_underlay_queues_drop_without_hiding_the_other_vector() {
        const NODE: &str =
            "nodekey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        const DISCO: &str =
            "discokey:404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
        let map = tailscale_embassy_core::control::parse_map_response(
            br#"{"Node":{"Addresses":["100.64.1.2/32"],"HomeDERP":1},"Peers":[{"ID":1,"Key":"nodekey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","DiscoKey":"discokey:404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","Addresses":["100.100.2.3/32"]}],"DERPMap":{"Regions":{"1":{"RegionID":1,"Nodes":[{"HostName":"derp1.example"}]}}}}"#,
        )
        .unwrap();
        let peer = NodePublicKey::parse(NODE).unwrap();
        let endpoint = Endpoint::new(Ipv4Addr::new(192, 168, 1, 9), 41641);
        let mut control =
            TailnetControlState::<1>::from_control_map(&NodePrivateKey::from_bytes([7; 32]), &map)
                .unwrap();
        assert_eq!(
            control.derp_peers.authenticate_direct_ping(
                DiscoPublicKey::parse(DISCO).unwrap(),
                Some(peer),
                endpoint,
            ),
            Some(peer)
        );
        let state = Mutex::<NoopRawMutex, _>::new(RefCell::new(control));
        let to_derp = Channel::<NoopRawMutex, PeerDatagram<4>, 1>::new();
        let to_direct = Channel::<NoopRawMutex, DirectDatagram<4>, 1>::new();
        let occupied_direct = DirectDatagram::new(peer, endpoint, b"old!").unwrap();
        to_direct.try_send(occupied_direct.clone()).unwrap();

        let packet = PeerDatagram::new(peer, b"new!").unwrap();
        dispatch_underlay(
            &state,
            packet.clone(),
            &to_derp.sender(),
            &to_direct.sender(),
        );

        assert_eq!(to_direct.try_receive(), Ok(occupied_direct));
        assert_eq!(to_derp.try_receive(), Ok(packet));

        let occupied_direct = DirectDatagram::new(peer, endpoint, b"keep").unwrap();
        let occupied_derp = PeerDatagram::new(peer, b"stay").unwrap();
        to_direct.try_send(occupied_direct.clone()).unwrap();
        to_derp.try_send(occupied_derp.clone()).unwrap();
        dispatch_underlay(
            &state,
            PeerDatagram::new(peer, b"drop").unwrap(),
            &to_derp.sender(),
            &to_direct.sender(),
        );
        assert_eq!(to_direct.try_receive(), Ok(occupied_direct));
        assert_eq!(to_derp.try_receive(), Ok(occupied_derp));
    }

    #[test]
    fn derp_disco_identity_and_reason_phrase_boundaries_fail_closed() {
        let peer = NodePublicKey::from_bytes([3; 32]);
        let other_peer = NodePublicKey::from_bytes([4; 32]);
        let disco = DiscoPublicKey::from_bytes([5; 32]);
        let other_disco = DiscoPublicKey::from_bytes([6; 32]);
        let ping = DiscoPing {
            source: disco,
            tx_id: [7; 12],
            node_key: Some(peer),
        };
        assert!(derp_ping_matches_peer(disco, ping, peer));
        assert!(derp_ping_matches_peer(
            disco,
            DiscoPing {
                node_key: None,
                ..ping
            },
            peer
        ));
        assert!(!derp_ping_matches_peer(other_disco, ping, peer));
        assert!(!derp_ping_matches_peer(disco, ping, other_peer));

        assert!(capture_first_line_byte(0, 1, 0, 32));
        assert!(!capture_first_line_byte(1, 1, 0, 32));
        assert!(!capture_first_line_byte(0, 1, 32, 32));
        assert!(has_unwritten_bytes(0, 1));
        assert!(!has_unwritten_bytes(1, 1));
        assert!(first_line_is_full(32, 32));
        assert!(!first_line_is_full(31, 32));
        assert!(should_flush_first_line(false, 1));
        assert!(!should_flush_first_line(true, 1));
        assert!(!should_flush_first_line(false, 0));
    }

    #[test]
    fn map_refresh_preserves_direct_endpoint_only_for_exact_peer_identity() {
        const NODE_A: &str =
            "nodekey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        const NODE_B: &str =
            "nodekey:202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
        const DISCO_A: &str =
            "discokey:404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
        const DISCO_B: &str =
            "discokey:606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f";
        let initial = tailscale_embassy_core::control::parse_map_response(
            br#"{"Node":{"Addresses":["100.64.1.2/32"],"HomeDERP":1},"Peers":[{"ID":1,"Key":"nodekey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","DiscoKey":"discokey:404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f","Addresses":["100.100.2.3/32"]}],"DERPMap":{"Regions":{"1":{"RegionID":1,"Nodes":[{"HostName":"derp1.example"}]}}}}"#,
        )
        .unwrap();
        let local_key = NodePrivateKey::from_bytes([7; 32]);
        let mut state = TailnetControlState::<2>::from_control_map(&local_key, &initial).unwrap();
        let node_a = NodePublicKey::parse(NODE_A).unwrap();
        let disco_a = DiscoPublicKey::parse(DISCO_A).unwrap();
        let endpoint = Endpoint::new(Ipv4Addr::new(192, 168, 1, 9), 41641);
        assert_eq!(
            state
                .derp_peers
                .authenticate_direct_ping(disco_a, Some(node_a), endpoint),
            Some(node_a)
        );

        state.apply_control_map(&initial).unwrap();
        assert_eq!(state.derp_peers.direct_endpoint_for(node_a), Some(endpoint));

        let changed_disco = tailscale_embassy_core::control::parse_map_response(
            br#"{"Node":{"Addresses":["100.64.1.2/32"],"HomeDERP":1},"Peers":[{"ID":1,"Key":"nodekey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","DiscoKey":"discokey:606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","Addresses":["100.100.2.3/32"]}],"DERPMap":{"Regions":{"1":{"RegionID":1,"Nodes":[{"HostName":"derp1.example"}]}}}}"#,
        )
        .unwrap();
        state.apply_control_map(&changed_disco).unwrap();
        assert_eq!(state.derp_peers.direct_endpoint_for(node_a), None);

        let disco_b = DiscoPublicKey::parse(DISCO_B).unwrap();
        assert_eq!(
            state
                .derp_peers
                .authenticate_direct_ping(disco_b, Some(node_a), endpoint),
            Some(node_a)
        );
        let changed_node = tailscale_embassy_core::control::parse_map_response(
            br#"{"Node":{"Addresses":["100.64.1.2/32"],"HomeDERP":1},"Peers":[{"ID":2,"Key":"nodekey:202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","DiscoKey":"discokey:606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f","Addresses":["100.100.2.4/32"]}],"DERPMap":{"Regions":{"1":{"RegionID":1,"Nodes":[{"HostName":"derp1.example"}]}}}}"#,
        )
        .unwrap();
        state.apply_control_map(&changed_node).unwrap();
        assert_eq!(
            state
                .derp_peers
                .direct_endpoint_for(NodePublicKey::parse(NODE_B).unwrap()),
            None
        );
    }

    #[test]
    fn live_control_state_applies_peer_changes_and_rejects_derp_move() {
        const NODE_A: &str =
            "nodekey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        const NODE_B: &str =
            "nodekey:202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
        let initial = tailscale_embassy_core::control::parse_map_response(
            br#"{"Node":{"Addresses":["100.64.1.2/32"],"HomeDERP":1},"Peers":[{"ID":1,"Key":"nodekey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","Addresses":["100.100.2.3/32"]}],"DERPMap":{"Regions":{"1":{"RegionID":1,"Nodes":[{"HostName":"derp1.example"}]}}}}"#,
        )
        .unwrap();
        let local_key = NodePrivateKey::from_bytes([7; 32]);
        let mut state = TailnetControlState::<2>::from_control_map(&local_key, &initial).unwrap();
        assert_eq!(
            state
                .router
                .peer_for_destination(Ipv4Addr::new(100, 100, 2, 3)),
            Some(NodePublicKey::parse(NODE_A).unwrap())
        );

        let changed = tailscale_embassy_core::control::parse_map_response(
            br#"{"Node":{"Addresses":["100.64.1.2/32"],"HomeDERP":1},"Peers":[{"ID":2,"Key":"nodekey:202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f","Addresses":["100.100.2.4/32"]}],"DERPMap":{"Regions":{"1":{"RegionID":1,"Nodes":[{"HostName":"derp1.example"}]}}}}"#,
        )
        .unwrap();
        state.apply_control_map(&changed).unwrap();
        assert_eq!(
            state
                .router
                .peer_for_destination(Ipv4Addr::new(100, 100, 2, 4)),
            Some(NodePublicKey::parse(NODE_B).unwrap())
        );
        assert_eq!(
            state
                .router
                .peer_for_destination(Ipv4Addr::new(100, 100, 2, 3)),
            None
        );

        let moved = tailscale_embassy_core::control::parse_map_response(
            br#"{"Node":{"Addresses":["100.64.1.2/32"],"HomeDERP":2},"DERPMap":{"Regions":{"2":{"RegionID":2,"Nodes":[{"HostName":"derp2.example"}]}}}}"#,
        )
        .unwrap();
        assert_eq!(
            state.apply_control_map(&moved),
            Err(TailnetStateError::DerpRegionChanged)
        );
    }

    #[test]
    #[cfg(feature = "host-tests")]
    fn raw_ipv4_injection_drives_tcp_syn_syn_ack_and_picoserve() {
        let mut state_a = TailnetDriverState::<TEST_MTU, 2, 2>::new();
        let mut state_b = TailnetDriverState::<TEST_MTU, 2, 2>::new();
        let mut resources_a = StackResources::<2>::new();
        let mut resources_b = StackResources::<2>::new();
        let address_a = Ipv4Addr::new(100, 64, 0, 1);
        let address_b = Ipv4Addr::new(100, 64, 0, 2);
        let (stack_a, mut runner_a, mut packets_a) =
            new_tailnet_stack(&mut state_a, &mut resources_a, address_a, 1);
        let (stack_b, mut runner_b, mut packets_b) =
            new_tailnet_stack(&mut state_b, &mut resources_b, address_b, 2);
        let saw_syn = Cell::new(false);
        let saw_syn_ack = Cell::new(false);
        let injections = Cell::new(0usize);

        pollster::block_on(async {
            let link = link_stacks(
                &mut packets_a,
                &mut packets_b,
                &saw_syn,
                &saw_syn_ack,
                &injections,
            );
            let service = async {
                let mut http_buffer = [0u8; DEFAULT_HTTP_BUFFER_SIZE];
                let mut server_rx = [0u8; DEFAULT_HTTP_TCP_RX_SIZE];
                let mut server_tx = [0u8; DEFAULT_HTTP_TCP_TX_SIZE];
                let server = run_http_server(
                    stack_b,
                    DEFAULT_HTTP_PORT,
                    &mut http_buffer,
                    &mut server_rx,
                    &mut server_tx,
                );
                let client = health_client(stack_a, address_b);
                match select(server, client).await {
                    Either::First(never) => match never {},
                    Either::Second(()) => {}
                }
            };

            match select4(runner_a.run(), runner_b.run(), link, service).await {
                Either4::First(never) | Either4::Second(never) | Either4::Third(never) => {
                    match never {}
                }
                Either4::Fourth(()) => {}
            }
        });

        assert!(saw_syn.get(), "client SYN was not emitted as raw IPv4");
        assert!(
            saw_syn_ack.get(),
            "server SYN-ACK was not emitted as raw IPv4"
        );
        assert!(
            injections.get() >= 2,
            "raw IPv4 packets were not injected into both stacks"
        );
    }

    #[cfg(feature = "host-tests")]
    async fn health_client(stack: Stack<'_>, server: Ipv4Addr) {
        for _ in 0..2 {
            request_and_expect(
                stack,
                server,
                b"GET /health HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
                "application/json",
                "{\"ok\":true}",
            )
            .await;
        }
    }

    #[cfg(feature = "host-tests")]
    async fn request_and_expect(
        stack: Stack<'_>,
        server: Ipv4Addr,
        request: &[u8],
        content_type: &str,
        body: &str,
    ) {
        let mut rx = [0u8; 1024];
        let mut tx = [0u8; 512];
        let mut socket = TcpSocket::new(stack, &mut rx, &mut tx);
        socket
            .connect(IpEndpoint::new(server.into(), DEFAULT_HTTP_PORT))
            .await
            .unwrap();
        let mut offset = 0;
        while offset < request.len() {
            offset += socket.write(&request[offset..]).await.unwrap();
        }
        socket.flush().await.unwrap();

        let mut response = [0u8; 512];
        let mut length = 0;
        while length < response.len() {
            match socket.read(&mut response[length..]).await {
                Ok(0) => break,
                Ok(read) => length += read,
                Err(_) if response[..length].ends_with(body.as_bytes()) => break,
                Err(error) => panic!("response read failed: {error:?}"),
            }
        }
        let response = core::str::from_utf8(&response[..length]).unwrap();
        assert!(
            response.starts_with("HTTP/1.1 200 OK\r\n"),
            "unexpected response: {response:?}"
        );
        assert!(
            response
                .lines()
                .any(|line| line.strip_prefix("Content-Type: ") == Some(content_type))
        );
        assert!(response.ends_with(body));
        socket.abort();
    }

    #[cfg(feature = "host-tests")]
    async fn link_stacks(
        a: &mut TailnetPacketIo<'_, TEST_MTU>,
        b: &mut TailnetPacketIo<'_, TEST_MTU>,
        saw_syn: &Cell<bool>,
        saw_syn_ack: &Cell<bool>,
        injections: &Cell<usize>,
    ) -> ! {
        let mut a_to_b = [0u8; TEST_MTU];
        let mut b_to_a = [0u8; TEST_MTU];
        loop {
            match select(
                a.receive_outbound(&mut a_to_b),
                b.receive_outbound(&mut b_to_a),
            )
            .await
            {
                Either::First(result) => {
                    let length = result.unwrap();
                    observe_tcp(&a_to_b[..length], true, saw_syn, saw_syn_ack);
                    b.inject_ipv4(&a_to_b[..length]).await.unwrap();
                    injections.set(injections.get() + 1);
                }
                Either::Second(result) => {
                    let length = result.unwrap();
                    observe_tcp(&b_to_a[..length], false, saw_syn, saw_syn_ack);
                    a.inject_ipv4(&b_to_a[..length]).await.unwrap();
                    injections.set(injections.get() + 1);
                }
            }
        }
    }

    #[cfg(feature = "host-tests")]
    fn observe_tcp(
        packet: &[u8],
        from_client: bool,
        saw_syn: &Cell<bool>,
        saw_syn_ack: &Cell<bool>,
    ) {
        let Ok(packet) = parse_ipv4(packet) else {
            return;
        };
        if packet.protocol != tailscale_embassy_core::packet::IP_PROTOCOL_TCP {
            return;
        }
        let flags = packet.bytes[IPV4_TCP_FLAGS_OFFSET];
        if from_client && flags & TCP_SYN != 0 && flags & TCP_ACK == 0 {
            saw_syn.set(true);
        }
        if !from_client && flags & (TCP_SYN | TCP_ACK) == (TCP_SYN | TCP_ACK) {
            saw_syn_ack.set(true);
        }
    }

    #[cfg(feature = "host-tests")]
    const IPV4_TCP_FLAGS_OFFSET: usize = 20 + 13;
    #[cfg(feature = "host-tests")]
    const TCP_SYN: u8 = 0x02;
    #[cfg(feature = "host-tests")]
    const TCP_ACK: u8 = 0x10;
}

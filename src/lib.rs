#![no_std]
#![forbid(unsafe_code)]
#![allow(async_fn_in_trait)]

//! `embassy-net` adapters for `tailscale-embassy-core`.
//!
//! The socket buffers, TLS record buffers, entropy source, and clock remain
//! caller-owned.  This crate supplies no executor and performs no allocation.

#[cfg(test)]
extern crate std;

pub mod tailnet;

use core::net::Ipv4Addr;

use embassy_net::tcp::TcpSocket;
use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{IpAddress, IpEndpoint, Stack, dns::DnsQueryType};
use embedded_io_async::{ErrorKind, ErrorType, Read, Write};
use rand_core::CryptoRngCore;
use tailscale_embassy_core::{
    Clock, Endpoint, TcpTransport, Timestamp, TlsTransport, TransportError, UdpTransport,
};

/// A caller-supplied source of authenticated Unix time.
///
/// A firmware implementation normally reads a network-synchronized RTC. The
/// monotonic half of [`EmbassyClock`] always comes from `embassy-time`.
pub trait UnixTime {
    /// Return seconds and nanoseconds since the Unix epoch.
    fn unix_time(&self) -> Option<(u64, u32)>;
}

/// Combines `embassy-time`'s monotonic clock with authenticated wall time.
pub struct EmbassyClock<U> {
    unix: U,
}

impl<U> EmbassyClock<U> {
    /// Construct a protocol clock around a firmware wall-clock source.
    pub const fn new(unix: U) -> Self {
        Self { unix }
    }
}

impl<U: UnixTime> Clock for EmbassyClock<U> {
    fn now(&self) -> Timestamp {
        let (unix_seconds, unix_nanos) = self.unix.unix_time().unwrap_or((0, 0));
        Timestamp {
            monotonic_nanos: embassy_time::Instant::now().as_nanos(),
            unix_seconds,
            unix_nanos: unix_nanos.min(999_999_999),
        }
    }
}

/// An owned `embassy-net` TCP socket usable by the platform-neutral core and
/// by `embedded-tls`.
pub struct EmbassyTcp<'a> {
    socket: TcpSocket<'a>,
}

impl<'a> EmbassyTcp<'a> {
    /// Create a socket over caller-owned fixed receive and transmit buffers.
    pub fn new(stack: Stack<'a>, rx: &'a mut [u8], tx: &'a mut [u8]) -> Self {
        Self {
            socket: TcpSocket::new(stack, rx, tx),
        }
    }

    /// Access the underlying socket for timeout and keepalive configuration.
    pub fn socket_mut(&mut self) -> &mut TcpSocket<'a> {
        &mut self.socket
    }

    /// Configure TCP keepalive and the maximum idle time in whole seconds.
    ///
    /// Taking scalar seconds keeps this adapter usable by applications that
    /// also depend on a different `embassy-time` release through their MCU
    /// HAL.
    pub fn configure_liveness(&mut self, keep_alive_seconds: u64, idle_timeout_seconds: u64) {
        self.socket
            .set_keep_alive(Some(embassy_time::Duration::from_secs(keep_alive_seconds)));
        self.socket
            .set_timeout(Some(embassy_time::Duration::from_secs(
                idle_timeout_seconds,
            )));
    }
}

impl ErrorType for EmbassyTcp<'_> {
    type Error = ErrorKind;
}

impl Read for EmbassyTcp<'_> {
    async fn read(&mut self, out: &mut [u8]) -> Result<usize, Self::Error> {
        self.socket
            .read(out)
            .await
            .map_err(|_| ErrorKind::ConnectionReset)
    }
}

impl Write for EmbassyTcp<'_> {
    async fn write(&mut self, data: &[u8]) -> Result<usize, Self::Error> {
        self.socket
            .write(data)
            .await
            .map_err(|_| ErrorKind::ConnectionReset)
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        self.socket
            .flush()
            .await
            .map_err(|_| ErrorKind::ConnectionReset)
    }
}

impl TcpTransport for EmbassyTcp<'_> {
    async fn connect(&mut self, endpoint: Endpoint) -> Result<(), TransportError> {
        self.socket
            .connect(to_embassy_endpoint(endpoint))
            .await
            .map_err(|_| TransportError::Connect)
    }

    async fn read(&mut self, out: &mut [u8]) -> Result<usize, TransportError> {
        Read::read(self, out)
            .await
            .map_err(|_| TransportError::Read)
    }

    async fn write(&mut self, data: &[u8]) -> Result<usize, TransportError> {
        Write::write(self, data)
            .await
            .map_err(|_| TransportError::Write)
    }

    async fn flush(&mut self) -> Result<(), TransportError> {
        Write::flush(self).await.map_err(|_| TransportError::Write)
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        self.socket.close();
        self.socket.flush().await.map_err(|_| TransportError::Write)
    }
}

/// An owned `embassy-net` UDP socket with caller-owned packet metadata and
/// payload rings.
pub struct EmbassyUdp<'a> {
    socket: UdpSocket<'a>,
}

impl<'a> EmbassyUdp<'a> {
    /// Create a UDP socket using fixed-capacity rings.
    pub fn new(
        stack: Stack<'a>,
        rx_meta: &'a mut [PacketMetadata],
        rx: &'a mut [u8],
        tx_meta: &'a mut [PacketMetadata],
        tx: &'a mut [u8],
    ) -> Self {
        Self {
            socket: UdpSocket::new(stack, rx_meta, rx, tx_meta, tx),
        }
    }
}

impl UdpTransport for EmbassyUdp<'_> {
    async fn bind(&mut self, local_port: u16) -> Result<u16, TransportError> {
        self.socket
            .bind(local_port)
            .map_err(|_| TransportError::Connect)?;
        Ok(self.socket.endpoint().port)
    }

    async fn send_to(&mut self, endpoint: Endpoint, data: &[u8]) -> Result<(), TransportError> {
        self.socket
            .send_to(data, to_embassy_endpoint(endpoint))
            .await
            .map_err(|_| TransportError::Write)
    }

    async fn recv_from(&mut self, out: &mut [u8]) -> Result<(usize, Endpoint), TransportError> {
        let (len, metadata) = self
            .socket
            .recv_from(out)
            .await
            .map_err(|_| TransportError::Read)?;
        Ok((len, from_embassy_endpoint(metadata.endpoint)?))
    }
}

/// Resolve the first IPv4 address for a DNS name using `embassy-net`.
pub async fn resolve_ipv4(stack: Stack<'_>, hostname: &str) -> Result<Ipv4Addr, TransportError> {
    let answers = stack
        .dns_query(hostname, DnsQueryType::A)
        .await
        .map_err(|_| TransportError::Dns)?;
    answers
        .first()
        .map(|address| match address {
            IpAddress::Ipv4(address) => *address,
        })
        .ok_or(TransportError::Dns)
}

/// A certificate-verifying `embedded-tls` session over a socket that has
/// already completed its TCP connect.
///
/// `connect_verified` checks that the control plane requested the endpoint and
/// name provisioned at construction, then performs a TLS 1.3 handshake. There
/// is deliberately no accept-all or insecure constructor.
pub struct VerifiedTls<'a, Socket, R, ClockType, const CERT_SIZE: usize>
where
    Socket: Read + Write + 'a,
    R: CryptoRngCore,
    ClockType: embedded_tls::TlsClock,
{
    client: Option<tls_transport::Client<'a, Socket, R, ClockType, CERT_SIZE>>,
    endpoint: Endpoint,
    server_name: &'a str,
}

impl<'a, Socket, R, ClockType, const CERT_SIZE: usize>
    VerifiedTls<'a, Socket, R, ClockType, CERT_SIZE>
where
    Socket: Read + Write + 'a,
    R: CryptoRngCore,
    ClockType: embedded_tls::TlsClock,
{
    /// Wrap a preconnected TCP socket and configure strict CA and DNS-name
    /// authentication.
    pub fn new(
        socket: Socket,
        endpoint: Endpoint,
        server_name: &'a str,
        read_record_buffer: &'a mut [u8],
        write_record_buffer: &'a mut [u8],
        rng: R,
        trust_anchor_der: &'a [u8],
    ) -> Result<Self, tls_transport::ConfigError> {
        let client = tls_transport::Client::new(
            socket,
            read_record_buffer,
            write_record_buffer,
            rng,
            trust_anchor_der,
            server_name,
        )?;
        Ok(Self {
            client: Some(client),
            endpoint,
            server_name,
        })
    }

    fn client_mut(
        &mut self,
    ) -> Result<&mut tls_transport::Client<'a, Socket, R, ClockType, CERT_SIZE>, TransportError>
    {
        self.client.as_mut().ok_or(TransportError::State)
    }
}

impl<'a, Socket, R, ClockType, const CERT_SIZE: usize> TlsTransport
    for VerifiedTls<'a, Socket, R, ClockType, CERT_SIZE>
where
    Socket: Read + Write + 'a,
    R: CryptoRngCore,
    ClockType: embedded_tls::TlsClock,
{
    async fn connect_verified(
        &mut self,
        endpoint: Endpoint,
        server_name: &str,
    ) -> Result<(), TransportError> {
        if endpoint != self.endpoint || server_name != self.server_name {
            return Err(TransportError::Authentication);
        }
        self.client_mut()?
            .open()
            .await
            .map_err(|_| TransportError::Authentication)
    }

    async fn read(&mut self, out: &mut [u8]) -> Result<usize, TransportError> {
        self.client_mut()?
            .read(out)
            .await
            .map_err(|_| TransportError::Read)
    }

    async fn write(&mut self, data: &[u8]) -> Result<usize, TransportError> {
        self.client_mut()?
            .write(data)
            .await
            .map_err(|_| TransportError::Write)
    }

    async fn flush(&mut self) -> Result<(), TransportError> {
        self.client_mut()?
            .flush()
            .await
            .map_err(|_| TransportError::Write)
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        let client = self.client.take().ok_or(TransportError::State)?;
        client
            .close()
            .await
            .map(|_| ())
            .map_err(|_| TransportError::Write)
    }
}

fn to_embassy_endpoint(endpoint: Endpoint) -> IpEndpoint {
    IpEndpoint::new(IpAddress::Ipv4(endpoint.address), endpoint.port)
}

fn from_embassy_endpoint(endpoint: IpEndpoint) -> Result<Endpoint, TransportError> {
    match endpoint.addr {
        IpAddress::Ipv4(address) => Ok(Endpoint::new(address, endpoint.port)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_round_trip_without_ipv6() {
        let endpoint = Endpoint::new(Ipv4Addr::new(203, 0, 113, 7), 443);
        assert_eq!(
            from_embassy_endpoint(to_embassy_endpoint(endpoint)),
            Ok(endpoint)
        );
    }
}

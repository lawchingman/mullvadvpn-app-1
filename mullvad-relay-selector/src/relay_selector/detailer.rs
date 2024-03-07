//! TODO(markus): Document

use std::net::{IpAddr, SocketAddr};

use mullvad_types::{
    constraints::Constraint,
    endpoint::{MullvadEndpoint, MullvadWireguardEndpoint},
    relay_list::{OpenVpnEndpoint, Relay, RelayEndpointData, WireguardEndpointData},
};
use talpid_types::net::{
    all_of_the_internet, wireguard::PeerConfig, Endpoint, IpVersion, TunnelType,
};

use crate::NormalSelectedRelay;

use super::matcher::{AnyTunnelMatcher, OpenVpnMatcher, WireguardMatcher};

/// TODO(markus): Document
#[derive(Clone, Debug)]
pub struct RelayDetailer<T: Detailer> {
    pub detailer: T,
}

impl<T: Detailer> RelayDetailer<T> {
    pub const fn new(detailer: T) -> Self {
        Self { detailer }
    }

    /// Populate a chosen [`Relay`] with connection details, such that a tunnel can
    /// be established.
    pub fn fill_in_the_details(&self, relay: Relay) -> Option<NormalSelectedRelay> {
        let endpoint_details = match relay.endpoint_data {
            RelayEndpointData::Openvpn => self.detailer.fill(&relay),
            RelayEndpointData::Wireguard(_) => self.detailer.fill(&relay),
            RelayEndpointData::Bridge => None,
        }?;

        Some(NormalSelectedRelay::new(endpoint_details, relay))
    }
}

pub trait Detailer {
    /// Constructs a MullvadEndpoint for a given Relay using extra data from the relay matcher
    /// itself.
    ///
    /// # Note
    /// This is a partial function because bridges are part of the [`Relay`] data model.
    /// If `relay` is actually an OpenVPN or Wireguard relay, the result should always be `Some(MullvadEndpoint)`.
    fn fill(&self, relay: &Relay) -> Option<MullvadEndpoint>;
}

impl Detailer for WireguardMatcher {
    fn fill(&self, relay: &Relay) -> Option<MullvadEndpoint> {
        // TODO(markus): Should not need this guard rail >:-) Rationale: We don't use the
        // information anyway, it's basically a null-check.
        //
        // if !self.is_matching_relay(relay) {
        //     return None;
        // }

        // TODO(markus): Move this fn
        fn get_address_for_wireguard_relay(
            wg_matcher: &WireguardMatcher,
            relay: &Relay,
        ) -> Option<IpAddr> {
            // TODO(markus): Don't really need an entire [`WireguardMatcher`] ..
            match wg_matcher.ip_version {
                Constraint::Any | Constraint::Only(IpVersion::V4) => {
                    Some(relay.ipv4_addr_in.into())
                }
                Constraint::Only(IpVersion::V6) => relay.ipv6_addr_in.map(|addr| addr.into()),
            }
        }

        // TODO(markus): Move this fn
        // TODO(markus): Can we isolate randomness?
        fn get_port_for_wireguard_relay(
            wg_matcher: &WireguardMatcher,
            data: &WireguardEndpointData,
        ) -> Option<u16> {
            // TODO(markus): Don't really need an entire [`WireguardMatcher`] ..
            match wg_matcher.port {
                Constraint::Any => {
                    let get_port_amount =
                        |range: &(u16, u16)| -> u64 { (1 + range.1 - range.0) as u64 };
                    let port_amount: u64 = data.port_ranges.iter().map(get_port_amount).sum();

                    if port_amount < 1 {
                        return None;
                    }

                    // TODO(markus): ???
                    use rand::Rng;
                    let mut port_index = rand::thread_rng().gen_range(0..port_amount);

                    for range in data.port_ranges.iter() {
                        let ports_in_range = get_port_amount(range);
                        if port_index < ports_in_range {
                            return Some(port_index as u16 + range.0);
                        }
                        port_index -= ports_in_range;
                    }
                    log::error!("Port selection algorithm is broken!");
                    None
                }
                Constraint::Only(port) => {
                    if data
                        .port_ranges
                        .iter()
                        .any(|range| (range.0 <= port && port <= range.1))
                    {
                        Some(port)
                    } else {
                        None
                    }
                }
            }
        }

        let host = get_address_for_wireguard_relay(self, relay)?;
        let port = get_port_for_wireguard_relay(self, &self.data)?;
        let peer_config = PeerConfig {
            public_key: relay
                .endpoint_data
                .unwrap_wireguard_ref()
                .public_key
                .clone(),
            endpoint: SocketAddr::new(host, port),
            allowed_ips: all_of_the_internet(),
            psk: None,
        };
        Some(MullvadEndpoint::Wireguard(MullvadWireguardEndpoint {
            peer: peer_config,
            exit_peer: None,
            ipv4_gateway: self.data.ipv4_gateway,
            ipv6_gateway: self.data.ipv6_gateway,
        }))
    }
}

impl Detailer for OpenVpnMatcher {
    fn fill(&self, relay: &Relay) -> Option<MullvadEndpoint> {
        // TODO(markus): Should not need this guard rail >:-) Rationale: We don't use the
        // information anyway, it's basically a null-check.
        //
        // if !self.is_matching_relay(relay) {
        //     return None;
        // }

        /// TODO(markus): Move this fn
        /// Choose a valid OpenVPN port.
        fn get_transport_port(ovpn_matcher: &OpenVpnMatcher) -> Option<&OpenVpnEndpoint> {
            let constraints_port = ovpn_matcher.constraints.port;
            let compatible_port_combo = |endpoint: &&OpenVpnEndpoint| match constraints_port {
                Constraint::Any => true,
                Constraint::Only(transport_port) => match transport_port.port {
                    Constraint::Any => transport_port.protocol == endpoint.protocol,
                    Constraint::Only(port) => {
                        port == endpoint.port && transport_port.protocol == endpoint.protocol
                    }
                },
            };

            // TODO(markus): ???
            use rand::seq::IteratorRandom;
            ovpn_matcher.data
            .ports
            .iter()
            .filter(compatible_port_combo)
            // TODO(markus): ???
            .choose(&mut rand::thread_rng())
        }

        get_transport_port(self).map(|endpoint| {
            MullvadEndpoint::OpenVpn(Endpoint::new(
                relay.ipv4_addr_in,
                endpoint.port,
                endpoint.protocol,
            ))
        })
    }
}

impl Detailer for AnyTunnelMatcher {
    fn fill(&self, relay: &Relay) -> Option<MullvadEndpoint> {
        #[cfg(not(target_os = "android"))]
        match self.tunnel_type {
            Constraint::Any => self
                .openvpn
                .fill(relay)
                .or_else(|| self.wireguard.fill(relay)),
            Constraint::Only(TunnelType::OpenVpn) => self.openvpn.fill(relay),
            Constraint::Only(TunnelType::Wireguard) => self.wireguard.fill(relay),
        }

        #[cfg(target_os = "android")]
        self.wireguard.fill(relay)
    }
}

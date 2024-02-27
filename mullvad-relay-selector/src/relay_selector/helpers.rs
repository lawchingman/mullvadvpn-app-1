//! This module contains various helper functions for the relay selector implementation.

// TODO(markus): Put all functions which does not use the RelaySelector/`self` paramter here.

use std::net::{IpAddr, SocketAddr};

use mullvad_types::{
    constraints::{Constraint, Match},
    custom_list::CustomListsSettings,
    endpoint::MullvadWireguardEndpoint,
    relay_constraints::{
        BridgeState, ObfuscationSettings, OpenVpnConstraints, Ownership, Providers,
        RelayConstraints, ResolvedLocationConstraint, SelectedObfuscation, TransportPort,
        Udp2TcpObfuscationSettings,
    },
    relay_list::{BridgeEndpointData, Relay, RelayEndpointData, WireguardEndpointData},
};
use talpid_types::net::{
    obfuscation::ObfuscatorConfig, proxy::CustomProxy, TransportProtocol, TunnelType,
};

use super::matcher::{EndpointMatcher, RelayMatcher, WireguardMatcher};
use super::{NormalSelectedRelay, SelectedObfuscator};
use crate::{
    constants::{WIREGUARD_EXIT_IP_VERSION, WIREGUARD_EXIT_PORT},
    error::Error,
};

/// Picks a relay using [Self::pick_random_relay_fn], using the `weight` member of each relay
/// as the weight function.
pub fn pick_random_relay(relays: &[Relay]) -> Option<&Relay> {
    pick_random_relay_fn(relays, |relay| relay.weight)
}

/// Pick a random relay from the given slice. Will return `None` if the given slice is empty.
/// If all of the relays have a weight of 0, one will be picked at random without bias,
/// otherwise roulette wheel selection will be used to pick only relays with non-zero
/// weights.
pub fn pick_random_relay_fn<RelayType>(
    relays: &[RelayType],
    weight_fn: impl Fn(&RelayType) -> u64,
) -> Option<&RelayType> {
    use rand::{seq::SliceRandom, Rng};
    let total_weight: u64 = relays.iter().map(&weight_fn).sum();
    let mut rng = rand::thread_rng();
    if total_weight == 0 {
        relays.choose(&mut rng)
    } else {
        // Pick a random number in the range 1..=total_weight. This choses the relay with a
        // non-zero weight.
        let mut i: u64 = rng.gen_range(1..=total_weight);
        Some(
            relays
                .iter()
                .find(|relay| {
                    i = i.saturating_sub(weight_fn(relay));
                    i == 0
                })
                .expect("At least one relay must've had a weight above 0"),
        )
    }
}

/// Picks a random bridge from a relay.
/// TODO(markus): Rip out state/RNG?
pub fn pick_random_bridge(data: &BridgeEndpointData, relay: &Relay) -> Option<CustomProxy> {
    use rand::seq::SliceRandom;
    if relay.endpoint_data != RelayEndpointData::Bridge {
        return None;
    }
    data.shadowsocks
        // TODO(markus): State bad, oogabooga
        .choose(&mut rand::thread_rng())
        .map(|shadowsocks_endpoint| {
            log::info!(
                "Selected Shadowsocks bridge {} at {}:{}/{}",
                relay.hostname,
                relay.ipv4_addr_in,
                shadowsocks_endpoint.port,
                shadowsocks_endpoint.protocol
            );
            shadowsocks_endpoint.to_proxy_settings(relay.ipv4_addr_in.into())
        })
}

/// Returns a random relay endpoint if any is matching the given constraints.
/// TODO(markus): This is apparently a hot path!
pub fn get_tunnel_endpoint_internal<T: EndpointMatcher>(
    relays: &[Relay],
    matcher: &RelayMatcher<T>,
) -> Result<NormalSelectedRelay, Error> {
    let matching_relays: Vec<Relay> = matcher.filter_matching_relay_list(relays.iter());

    // TODO(markus): This should be at the top of the callchain
    pick_random_relay(&matching_relays)
        .and_then(|selected_relay| {
            let endpoint = matcher.mullvad_endpoint(selected_relay);
            let addr_in = endpoint
                .as_ref()
                .map(|endpoint| endpoint.to_endpoint().address.ip())
                .unwrap_or_else(|| IpAddr::from(selected_relay.ipv4_addr_in));
            log::info!("Selected relay {} at {}", selected_relay.hostname, addr_in);
            endpoint.map(|endpoint| NormalSelectedRelay::new(endpoint, selected_relay.clone()))
        })
        .ok_or(Error::NoRelay)
}

pub fn wireguard_exit_matcher(wg: WireguardEndpointData) -> WireguardMatcher {
    let mut tunnel = WireguardMatcher::from_endpoint(wg);
    tunnel.ip_version = WIREGUARD_EXIT_IP_VERSION;
    tunnel.port = WIREGUARD_EXIT_PORT;
    tunnel
}

pub fn get_obfuscator_inner(
    udp2tcp_ports: &[u16],
    obfuscation_settings: &ObfuscationSettings,
    relay: &Relay,
    endpoint: &MullvadWireguardEndpoint,
    retry_attempt: u32,
) -> Result<Option<SelectedObfuscator>, Error> {
    match obfuscation_settings.selected_obfuscation {
        SelectedObfuscation::Auto => Ok(get_auto_obfuscator(
            udp2tcp_ports,
            &obfuscation_settings.udp2tcp,
            relay,
            endpoint,
            retry_attempt,
        )),
        SelectedObfuscation::Off => Ok(None),
        SelectedObfuscation::Udp2Tcp => Ok(Some(
            get_udp2tcp_obfuscator(
                udp2tcp_ports,
                &obfuscation_settings.udp2tcp,
                relay,
                endpoint,
                retry_attempt,
            )
            .ok_or(Error::NoObfuscator)?,
        )),
    }
}

pub fn get_auto_obfuscator(
    udp2tcp_ports: &[u16],
    obfuscation_settings: &Udp2TcpObfuscationSettings,
    relay: &Relay,
    endpoint: &MullvadWireguardEndpoint,
    retry_attempt: u32,
) -> Option<SelectedObfuscator> {
    let obfuscation_attempt = get_auto_obfuscator_retry_attempt(retry_attempt)?;
    get_udp2tcp_obfuscator(
        udp2tcp_ports,
        obfuscation_settings,
        relay,
        endpoint,
        obfuscation_attempt,
    )
}

pub fn get_udp2tcp_obfuscator(
    udp2tcp_ports: &[u16], // TODO(markus): Create/use existing type that reflects that these are ports?
    obfuscation_settings: &Udp2TcpObfuscationSettings,
    relay: &Relay,
    endpoint: &MullvadWireguardEndpoint,
    retry_attempt: u32,
) -> Option<SelectedObfuscator> {
    let udp2tcp_endpoint = if obfuscation_settings.port.is_only() {
        udp2tcp_ports
            .iter()
            .find(|&candidate| obfuscation_settings.port == Constraint::Only(*candidate))
    } else {
        udp2tcp_ports.get(retry_attempt as usize % udp2tcp_ports.len())
    };
    udp2tcp_endpoint
        .map(|udp2tcp_endpoint| ObfuscatorConfig::Udp2Tcp {
            endpoint: SocketAddr::new(endpoint.peer.endpoint.ip(), *udp2tcp_endpoint),
        })
        .map(|config| SelectedObfuscator {
            config,
            relay: relay.clone(),
        })
}

// TODO(markus): These functions below are all slated for removal.
// TODO(markus): Obsolete, remove
pub const fn should_use_bridge(retry_attempt: u32) -> bool {
    // shouldn't use a bridge for the first 3 times
    retry_attempt > 3 &&
        // i.e. 4th and 5th with bridge, 6th & 7th without
        // The test is to see whether the current _couple of connections_ is even or not.
        // | retry_attempt                | 4 | 5 | 6 | 7 | 8 | 9 |
        // | (retry_attempt % 4) < 2      | t | t | f | f | t | t |
        (retry_attempt % 4) < 2
}

// TODO(markus): Obsolete, remove.
pub const fn preferred_wireguard_port(retry_attempt: u32) -> Constraint<u16> {
    // Alternate between using a random port and port 53
    if retry_attempt % 2 == 0 {
        Constraint::Any
    } else {
        Constraint::Only(53)
    }
}

// TODO(markus): Obsolete, remove.
pub const fn preferred_openvpn_constraints(
    retry_attempt: u32,
) -> (Constraint<u16>, TransportProtocol) {
    // Prefer UDP by default. But if that has failed a couple of times, then try TCP port
    // 443, which works for many with UDP problems. After that, just alternate
    // between protocols.
    // If the tunnel type constraint is set OpenVpn, from the 4th attempt onwards, the first
    // two retry attempts OpenVpn constraints should be set to TCP as a bridge will be used,
    // and to UDP or TCP for the next two attempts.
    match retry_attempt {
        0 | 1 => (Constraint::Any, TransportProtocol::Udp),
        2 | 3 => (Constraint::Only(443), TransportProtocol::Tcp),
        attempt if attempt % 4 < 2 => (Constraint::Any, TransportProtocol::Tcp),
        attempt if attempt % 4 == 2 => (Constraint::Any, TransportProtocol::Udp),
        _ => (Constraint::Any, TransportProtocol::Tcp),
    }
}

/// Return the preferred constraints, on attempt `retry_attempt`, given no other constraints
// TODO(markus): Obsolete, remove
pub const fn preferred_tunnel_constraints(
    retry_attempt: u32,
) -> (Constraint<u16>, TransportProtocol, TunnelType) {
    // Use WireGuard on the first three attempts, then OpenVPN
    match retry_attempt {
        0..=2 => (
            preferred_wireguard_port(retry_attempt),
            TransportProtocol::Udp,
            TunnelType::Wireguard,
        ),
        _ => {
            let (preferred_port, preferred_protocol) =
                preferred_openvpn_constraints(retry_attempt - 2);
            (preferred_port, preferred_protocol, TunnelType::OpenVpn)
        }
    }
}

/// Return the preferred constraints, on attempt `retry_attempt`, for matching locations
// TODO(markus): Obsolete, remove
pub fn preferred_tunnel_constraints_for_location(
    relays: &[Relay],
    retry_attempt: u32,
    location: &Constraint<ResolvedLocationConstraint>,
    providers: &Constraint<Providers>,
    ownership: Constraint<Ownership>,
) -> (Constraint<u16>, TransportProtocol, TunnelType) {
    let (location_supports_wg, location_supports_openvpn) = {
        let mut active_location_relays = relays.iter().filter(|relay| {
            relay.active
                && location.matches_with_opts(relay, true)
                && providers.matches(relay)
                && ownership.matches(relay)
        });
        let location_supports_wg = active_location_relays
            .clone()
            .any(|relay| matches!(relay.endpoint_data, RelayEndpointData::Wireguard(_)));
        let location_supports_openvpn = active_location_relays
            .any(|relay| matches!(relay.endpoint_data, RelayEndpointData::Openvpn));

        (location_supports_wg, location_supports_openvpn)
    };
    match (location_supports_wg, location_supports_openvpn) {
        (true, true) | (false, false) => preferred_tunnel_constraints(retry_attempt),
        (true, false) => {
            let port = preferred_wireguard_port(retry_attempt);
            (port, TransportProtocol::Udp, TunnelType::Wireguard)
        }
        (false, true) => {
            let (port, transport) = preferred_openvpn_constraints(retry_attempt);
            (port, transport, TunnelType::OpenVpn)
        }
    }
}

// This function ignores the tunnel type constraint on purpose.
// TODO(markus): Obsolete, remove
#[cfg_attr(target_os = "android", allow(dead_code))]
pub fn preferred_constraints(
    relays: &[Relay],
    original_constraints: &RelayConstraints,
    bridge_state: BridgeState,
    retry_attempt: u32,
    custom_lists: &CustomListsSettings,
) -> RelayConstraints {
    let location = ResolvedLocationConstraint::from_constraint(
        original_constraints.location.clone(),
        custom_lists,
    );
    let (preferred_port, preferred_protocol, preferred_tunnel) =
        preferred_tunnel_constraints_for_location(
            relays,
            retry_attempt,
            &location,
            &original_constraints.providers,
            original_constraints.ownership,
        );

    let mut relay_constraints = original_constraints.clone();
    relay_constraints.openvpn_constraints = Default::default();

    // Highest priority preference. Where we prefer OpenVPN using UDP. But without changing
    // any constraints that are explicitly specified.
    match original_constraints.tunnel_protocol {
        // If no tunnel protocol is selected, use preferred constraints
        Constraint::Any => {
            if bridge_state == BridgeState::On {
                relay_constraints.openvpn_constraints = OpenVpnConstraints {
                    port: Constraint::Only(TransportPort {
                        protocol: TransportProtocol::Tcp,
                        port: Constraint::Any,
                    }),
                };
            } else if original_constraints.openvpn_constraints.port.is_any() {
                relay_constraints.openvpn_constraints = OpenVpnConstraints {
                    port: Constraint::Only(TransportPort {
                        protocol: preferred_protocol,
                        port: preferred_port,
                    }),
                };
            } else {
                relay_constraints.openvpn_constraints = original_constraints.openvpn_constraints;
            }

            if relay_constraints.wireguard_constraints.port.is_any() {
                relay_constraints.wireguard_constraints.port = preferred_port;
            }

            relay_constraints.tunnel_protocol = Constraint::Only(preferred_tunnel);
        }
        Constraint::Only(TunnelType::OpenVpn) => {
            let openvpn_constraints = &mut relay_constraints.openvpn_constraints;
            *openvpn_constraints = original_constraints.openvpn_constraints;
            if bridge_state == BridgeState::On && openvpn_constraints.port.is_any() {
                openvpn_constraints.port = Constraint::Only(TransportPort {
                    protocol: TransportProtocol::Tcp,
                    port: Constraint::Any,
                });
            } else if openvpn_constraints.port.is_any() {
                let (preferred_port, preferred_protocol) =
                    preferred_openvpn_constraints(retry_attempt);
                openvpn_constraints.port = Constraint::Only(TransportPort {
                    protocol: preferred_protocol,
                    port: preferred_port,
                });
            }
        }
        Constraint::Only(TunnelType::Wireguard) => {
            relay_constraints.wireguard_constraints =
                original_constraints.wireguard_constraints.clone();
            if relay_constraints.wireguard_constraints.port.is_any() {
                relay_constraints.wireguard_constraints.port =
                    preferred_wireguard_port(retry_attempt);
            }
        }
    };

    relay_constraints
}

// TODO(markus): Obsolete, remove
pub const fn get_auto_obfuscator_retry_attempt(retry_attempt: u32) -> Option<u32> {
    match retry_attempt % 4 {
        0 | 1 => None,
        // when the retry attempt is 2-3, 6-7, 10-11 ... obfuscation will be used
        filtered_retry => Some(retry_attempt / 4 + filtered_retry - 2),
    }
}

//! This module contains various helper functions for the relay selector implementation.

// TODO(markus): Put all functions which does not use the RelaySelector/`self` paramter here.

use std::net::{IpAddr, SocketAddr};

use mullvad_types::{
    constraints::Constraint,
    endpoint::MullvadWireguardEndpoint,
    relay_constraints::{ObfuscationSettings, SelectedObfuscation, Udp2TcpObfuscationSettings},
    relay_list::{BridgeEndpointData, Relay, RelayEndpointData, WireguardEndpointData},
};
use talpid_types::net::{obfuscation::ObfuscatorConfig, proxy::CustomProxy};

use super::matcher::{EndpointMatcher, RelayMatcher, WireguardMatcher};
use super::{NormalSelectedRelay, SelectedObfuscator};
use crate::{
    constants::{WIREGUARD_EXIT_IP_VERSION, WIREGUARD_EXIT_PORT},
    error::Error,
    SelectorConfig,
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
    let shadowsocks_endpoint = data.shadowsocks.choose(&mut rand::thread_rng());
    if let Some(shadowsocks_endpoint) = shadowsocks_endpoint {
        log::info!(
            "Selected Shadowsocks bridge {} at {}:{}/{}",
            relay.hostname,
            relay.ipv4_addr_in,
            shadowsocks_endpoint.port,
            shadowsocks_endpoint.protocol
        );
    }
    shadowsocks_endpoint
        .map(|endpoint_data| endpoint_data.to_proxy_settings(relay.ipv4_addr_in.into()))
}

/// Returns a random relay endpoint if any is matching the given constraints.
/// TODO(markus): This is apparently a hot path!
pub fn get_tunnel_endpoint_internal<'a, T, R>(
    relays: R,
    matcher: &RelayMatcher<T>,
) -> Result<NormalSelectedRelay, Error>
where
    T: EndpointMatcher,
    R: Iterator<Item = &'a Relay> + Clone,
{
    let matching_relays: Vec<Relay> = matcher.filter_matching_relay_list(relays);

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
    retry_attempt: usize,
) -> Result<Option<SelectedObfuscator>, Error> {
    match obfuscation_settings.selected_obfuscation {
        SelectedObfuscation::Off => Ok(None),
        SelectedObfuscation::Udp2Tcp => Ok(get_udp2tcp_obfuscator(
            udp2tcp_ports,
            &obfuscation_settings.udp2tcp,
            relay,
            endpoint,
            retry_attempt,
        )),
        SelectedObfuscation::Auto => {
            let obfuscation_settings = &obfuscation_settings.udp2tcp;
            match get_auto_obfuscator_retry_attempt(retry_attempt) {
                Some(obfuscation_attempt) => Ok(get_udp2tcp_obfuscator(
                    udp2tcp_ports,
                    obfuscation_settings,
                    relay,
                    endpoint,
                    obfuscation_attempt,
                )),
                None => Ok(None),
            }
        }
    }
}

pub fn get_udp2tcp_obfuscator(
    udp2tcp_ports: &[u16], // TODO(markus): Create/use existing type that reflects that these are ports?
    obfuscation_settings: &Udp2TcpObfuscationSettings,
    relay: &Relay,
    endpoint: &MullvadWireguardEndpoint,
    retry_attempt: usize,
) -> Option<SelectedObfuscator> {
    let udp2tcp_endpoint = if obfuscation_settings.port.is_only() {
        udp2tcp_ports
            .iter()
            .find(|&candidate| obfuscation_settings.port == Constraint::Only(*candidate))
    } else {
        udp2tcp_ports.get(retry_attempt % udp2tcp_ports.len())
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

// TODO(markus): This is not enough, right?
pub const fn should_use_bridge(config: &SelectorConfig) -> bool {
    use mullvad_types::relay_constraints::BridgeState;
    match config.bridge_state {
        BridgeState::On => true,
        BridgeState::Off => false,
        // TODO(markus): This should really be expressed as a constraint ..
        BridgeState::Auto => false,
    }
}

// TODO(markus): Obsolete, remove
pub const fn get_auto_obfuscator_retry_attempt(retry_attempt: usize) -> Option<usize> {
    match retry_attempt % 4 {
        0 | 1 => None,
        // when the retry attempt is 2-3, 6-7, 10-11 ... obfuscation will be used
        filtered_retry => Some(retry_attempt / 4 + filtered_retry - 2),
    }
}

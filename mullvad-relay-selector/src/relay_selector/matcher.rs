// TODO(markus): Remove
#![allow(dead_code, unused)]
use mullvad_types::{
    constraints::{Constraint, Match},
    custom_list::CustomListsSettings,
    endpoint::{MullvadEndpoint, MullvadWireguardEndpoint},
    location::Location,
    relay_constraints::{
        BridgeState, InternalBridgeConstraints, LocationConstraint, OpenVpnConstraints, Ownership,
        Providers, RelayConstraints, RelayConstraintsFilter, ResolvedLocationConstraint,
        TransportPort, WireguardConstraints,
    },
    relay_list::{
        OpenVpnEndpoint, OpenVpnEndpointData, Relay, RelayEndpointData, WireguardEndpointData,
    },
};
use rand::{
    seq::{IteratorRandom, SliceRandom},
    Rng,
};
use std::net::{IpAddr, SocketAddr};
use talpid_types::net::{
    all_of_the_internet, wireguard, Endpoint, IpVersion, TransportProtocol, TunnelType,
};

use crate::NormalSelectedRelay;

use super::helpers;

#[derive(Clone)]
pub struct RelayMatcher<T: EndpointMatcher> {
    /// Locations allowed to be picked from. In the case of custom lists this may be multiple
    /// locations. In normal circumstances this contains only 1 location.
    pub locations: Constraint<ResolvedLocationConstraint>,
    /// Relay providers allowed to be picked from.
    pub providers: Constraint<Providers>,
    /// Relay ownership allowed to be picked from.
    pub ownership: Constraint<Ownership>,
    /// Concrete representation of [`RelayConstraints`] or [`BridgeConstraints`].
    pub endpoint_matcher: T,
}

#[derive(Clone, Debug)]
pub struct RelayDetailer<T: EndpointMatcher> {
    pub endpoint_matcher: T,
}

impl<T: EndpointMatcher> RelayDetailer<T> {
    pub const fn new(endpoint_matcher: T) -> Self {
        Self { endpoint_matcher }
    }

    /// Populate a chosen [`Relay`] with connection details, such that a tunnel can
    /// be established.
    pub fn fill_in_the_details(&self, relay: Relay) -> Option<NormalSelectedRelay> {
        let endpoint_details = match relay.endpoint_data {
            RelayEndpointData::Openvpn => self.endpoint_matcher.mullvad_endpoint(&relay),
            RelayEndpointData::Wireguard(_) => self.endpoint_matcher.mullvad_endpoint(&relay),
            RelayEndpointData::Bridge => None,
        }?;

        Some(NormalSelectedRelay::new(endpoint_details, relay))
    }
}

impl RelayMatcher<AnyTunnelMatcher> {
    pub fn new(
        constraints: RelayConstraints,
        openvpn_data: OpenVpnEndpointData,
        brige_state: BridgeState,
        wireguard_data: WireguardEndpointData,
        custom_lists: &CustomListsSettings,
    ) -> Self {
        Self {
            locations: ResolvedLocationConstraint::from_constraint(
                constraints.location,
                custom_lists,
            ),
            providers: constraints.providers,
            ownership: constraints.ownership,
            endpoint_matcher: AnyTunnelMatcher {
                wireguard: WireguardMatcher::new(constraints.wireguard_constraints, wireguard_data),
                openvpn: OpenVpnMatcher::new(
                    constraints.openvpn_constraints,
                    openvpn_data,
                    brige_state,
                ),
                tunnel_type: constraints.tunnel_protocol,
            },
        }
    }
}

impl RelayMatcher<WireguardMatcher> {
    pub fn set_peer(&mut self, peer: Relay) {
        self.endpoint_matcher.peer = Some(peer);
    }
}

impl<T: EndpointMatcher> RelayMatcher<T> {
    /// Filter a list of relays and their endpoints based on constraints.
    /// Only relays with (and including) matching endpoints are returned.
    // TODO(markus): Should this function simply return an iterator?
    // TODO(markus): Turn this into a function which can simply be passed to `iter.filter`
    pub fn filter_matching_relay_list<'a, R: Iterator<Item = &'a Relay> + Clone>(
        &self,
        relays: R,
    ) -> Vec<Relay> {
        let shortlist = relays
            // Filter on active relays
            .filter(|relay| filter_on_active(relay))
            // Filter by location
            .filter(|relay| filter_on_location(&self.locations, relay))
            // Filter by ownership
            .filter(|relay| filter_on_ownership(&self.ownership, relay))
            // Filter by providers
            .filter(|relay| filter_on_providers(&self.providers, relay))
            // Filter on relay type & relay specific properties
            .filter(|relay| self.endpoint_matcher.is_matching_relay(relay));

        // The last filtering to be done is on the `include_in_country` attribute found on each
        // relay. A regular, user-facing relay will have `include_in_country` set to true.
        // If a relay has `include_in_country` set to false, they are purposely hidden than
        // other relays. We should only consider those if there are no regular candidates left.
        let ignore_include_in_country = !shortlist.clone().any(|relay| relay.include_in_country);
        shortlist
            .filter(|relay| {
                self.locations
                    .matches_with_opts(relay, ignore_include_in_country)
            })
            .cloned()
            .collect()
    }
}

/// EndpointMatcher allows to abstract over different tunnel-specific or bridge constraints.
/// This enables one to not have false dependencies on OpenVpn specific constraints when
/// selecting only WireGuard tunnels.
pub trait EndpointMatcher: Clone {
    /// Returns whether the relay has matching endpoints.
    fn is_matching_relay(&self, relay: &Relay) -> bool;
    /// Constructs a MullvadEndpoint for a given Relay using extra data from the relay matcher
    /// itself.
    fn mullvad_endpoint(&self, relay: &Relay) -> Option<MullvadEndpoint>;
}

impl EndpointMatcher for OpenVpnMatcher {
    fn is_matching_relay(&self, relay: &Relay) -> bool {
        filter_openvpn(relay) && openvpn_filter_on_port(self.constraints, &self.data)
    }

    /// TODO(markus): This function does not only filter, it actively produces
    /// a new [`MullvadEndpoint`]. This should be split up.
    fn mullvad_endpoint(&self, relay: &Relay) -> Option<MullvadEndpoint> {
        if !self.is_matching_relay(relay) {
            return None;
        }

        self.get_transport_port().map(|endpoint| {
            MullvadEndpoint::OpenVpn(Endpoint::new(
                relay.ipv4_addr_in,
                endpoint.port,
                endpoint.protocol,
            ))
        })
    }
}
#[derive(Clone)]
pub struct AnyTunnelMatcher {
    pub wireguard: WireguardMatcher,
    pub openvpn: OpenVpnMatcher,
    /// in the case that a user hasn't specified a tunnel protocol, the relay
    /// selector might still construct preferred constraints that do select a
    /// specific tunnel protocol, which is why the tunnel type may be specified
    /// in the `AnyTunnelMatcher`.
    pub tunnel_type: Constraint<TunnelType>,
}

impl EndpointMatcher for AnyTunnelMatcher {
    fn is_matching_relay(&self, relay: &Relay) -> bool {
        match self.tunnel_type {
            Constraint::Any => {
                self.wireguard.is_matching_relay(relay) || self.openvpn.is_matching_relay(relay)
            }
            Constraint::Only(TunnelType::OpenVpn) => self.openvpn.is_matching_relay(relay),
            Constraint::Only(TunnelType::Wireguard) => self.wireguard.is_matching_relay(relay),
        }
    }

    fn mullvad_endpoint(&self, relay: &Relay) -> Option<MullvadEndpoint> {
        #[cfg(not(target_os = "android"))]
        match self.tunnel_type {
            Constraint::Any => self
                .openvpn
                .mullvad_endpoint(relay)
                .or_else(|| self.wireguard.mullvad_endpoint(relay)),
            Constraint::Only(TunnelType::OpenVpn) => self.openvpn.mullvad_endpoint(relay),
            Constraint::Only(TunnelType::Wireguard) => self.wireguard.mullvad_endpoint(relay),
        }

        #[cfg(target_os = "android")]
        self.wireguard.mullvad_endpoint(relay)
    }
}

#[derive(Default, Clone)]
pub struct WireguardMatcher {
    /// The peer is an already selected peer relay to be used with multihop.
    /// It's stored here so we can exclude it from further selections being made.
    pub peer: Option<Relay>,
    pub port: Constraint<u16>,
    pub ip_version: Constraint<IpVersion>,

    pub data: WireguardEndpointData,
}

impl WireguardMatcher {
    pub fn new(constraints: WireguardConstraints, data: WireguardEndpointData) -> Self {
        Self {
            peer: None,
            port: constraints.port,
            ip_version: constraints.ip_version,
            data,
        }
    }

    pub fn new_matcher(
        // TODO(markus): Might be able to remove custom lists when geo location stuff is removed from `RelayMatcher`
        relay_constraints: RelayConstraints,
        constraints: WireguardConstraints,
        data: WireguardEndpointData,
        // TODO(markus): Might be able to remove custom lists when geo location stuff is removed from `RelayMatcher`
        custom_lists: &CustomListsSettings,
    ) -> RelayMatcher<Self> {
        RelayMatcher {
            locations: ResolvedLocationConstraint::from_constraint(
                relay_constraints.location,
                custom_lists,
            ),
            providers: relay_constraints.providers,
            ownership: relay_constraints.ownership,
            endpoint_matcher: WireguardMatcher::new(constraints, data),
        }
    }

    /// Special cased version of [`WireguardMatcher::new_matcher`] where
    /// `wireguard_constraints.entry_location` is set as the entry location
    /// constraint.
    ///
    /// TODO(markus): Can probably be removed if location is lifted out of [`RelayMatcher`].
    pub fn new_entry_matcher(
        // TODO(markus): Might be able to remove custom lists when geo location stuff is removed from `RelayMatcher`
        relay_constraints: RelayConstraints,
        constraints: WireguardConstraints,
        data: WireguardEndpointData,
        // TODO(markus): Might be able to remove custom lists when geo location stuff is removed from `RelayMatcher`
        custom_lists: &CustomListsSettings,
    ) -> RelayMatcher<Self> {
        let locations = ResolvedLocationConstraint::from_constraint(
            relay_constraints
                .wireguard_constraints
                .entry_location
                .clone(),
            custom_lists,
        );

        RelayMatcher {
            locations,
            providers: relay_constraints.providers,
            ownership: relay_constraints.ownership,
            endpoint_matcher: WireguardMatcher::new(constraints, data),
        }
    }

    /// Special cased version of [`WireguardMatcher::new_matcher`] where
    /// ..
    ///
    /// TODO(markus): Can probably be removed if location is lifted out of [`RelayMatcher`].
    pub fn new_exit_matcher(
        // TODO(markus): Might be able to remove custom lists when geo location stuff is removed from `RelayMatcher`
        relay_constraints: RelayConstraints,
        constraints: WireguardConstraints,
        data: WireguardEndpointData,
        // TODO(markus): Might be able to remove custom lists when geo location stuff is removed from `RelayMatcher`
        custom_lists: &CustomListsSettings,
    ) -> RelayMatcher<Self> {
        let mut matcher =
            Self::new_matcher(relay_constraints, constraints, data.clone(), custom_lists);
        matcher.endpoint_matcher = helpers::wireguard_exit_matcher(data);
        matcher
    }

    // TODO(markus): This is not a filter function
    pub fn from_endpoint(data: WireguardEndpointData) -> Self {
        Self {
            data,
            ..Default::default()
        }
    }

    // TODO(markus): This is not a filter function
    fn wg_data_to_endpoint(
        &self,
        relay: &Relay,
        data: &WireguardEndpointData,
    ) -> Option<MullvadEndpoint> {
        let host = self.get_address_for_wireguard_relay(relay)?;
        let port = self.get_port_for_wireguard_relay(data)?;
        let peer_config = wireguard::PeerConfig {
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
            ipv4_gateway: data.ipv4_gateway,
            ipv6_gateway: data.ipv6_gateway,
        }))
    }

    // TODO(markus): This is not a filter function
    fn get_address_for_wireguard_relay(&self, relay: &Relay) -> Option<IpAddr> {
        match self.ip_version {
            Constraint::Any | Constraint::Only(IpVersion::V4) => Some(relay.ipv4_addr_in.into()),
            Constraint::Only(IpVersion::V6) => relay.ipv6_addr_in.map(|addr| addr.into()),
        }
    }

    // TODO(markus): This is not a filter function
    fn get_port_for_wireguard_relay(&self, data: &WireguardEndpointData) -> Option<u16> {
        match self.port {
            Constraint::Any => {
                let get_port_amount =
                    |range: &(u16, u16)| -> u64 { (1 + range.1 - range.0) as u64 };
                let port_amount: u64 = data.port_ranges.iter().map(get_port_amount).sum();

                if port_amount < 1 {
                    return None;
                }

                // TODO(markus): ???
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
}

impl EndpointMatcher for WireguardMatcher {
    // TODO(markus): Decompose this next!
    fn is_matching_relay(&self, relay: &Relay) -> bool {
        match &self.peer {
            Some(peer) => filter_wireguard(relay) && are_distinct_relays(peer, relay),
            None => filter_wireguard(relay),
        }
    }

    // TODO(markus): This function should be converted to only the mapping part, not the filtering
    // part.
    // TODO(markus): Remove this
    fn mullvad_endpoint(&self, relay: &Relay) -> Option<MullvadEndpoint> {
        if !self.is_matching_relay(relay) {
            return None;
        }
        self.wg_data_to_endpoint(relay, &self.data)
    }
}

#[derive(Debug, Clone)]
pub struct OpenVpnMatcher {
    pub constraints: OpenVpnConstraints,
    pub data: OpenVpnEndpointData,
}

impl OpenVpnMatcher {
    pub fn new(
        mut constraints: OpenVpnConstraints,
        data: OpenVpnEndpointData,
        bridge_state: BridgeState,
    ) -> Self {
        // TODO(markus): Seems like a hack
        if constraints.port.is_any() && bridge_state == BridgeState::On {
            constraints.port = Constraint::Only(TransportPort {
                protocol: TransportProtocol::Tcp,
                port: Constraint::Any,
            });
        }
        Self { constraints, data }
    }

    /// Choose a valid OpenVPN port.
    ///
    /// TODO(markus): This is not a filter function!
    fn get_transport_port(&self) -> Option<&OpenVpnEndpoint> {
        let constraints_port = self.constraints.port;
        let compatible_port_combo = |endpoint: &&OpenVpnEndpoint| match constraints_port {
            Constraint::Any => true,
            Constraint::Only(transport_port) => match transport_port.port {
                Constraint::Any => transport_port.protocol == endpoint.protocol,
                Constraint::Only(port) => {
                    port == endpoint.port && transport_port.protocol == endpoint.protocol
                }
            },
        };

        self.data
            .ports
            .iter()
            .filter(compatible_port_combo)
            // TODO(markus): ???
            .choose(&mut rand::thread_rng())
    }
}

#[derive(Clone)]
pub struct BridgeMatcher;

impl BridgeMatcher {
    pub fn new_matcher(
        // TODO(markus): Might be able to remove custom lists when geo location stuff is removed from `RelayMatcher`
        relay_constraints: InternalBridgeConstraints,
        // TODO(markus): Might be able to remove custom lists when geo location stuff is removed from `RelayMatcher`
        custom_lists: &CustomListsSettings,
    ) -> RelayMatcher<Self> {
        RelayMatcher {
            locations: ResolvedLocationConstraint::from_constraint(
                relay_constraints.location,
                custom_lists,
            ),
            providers: relay_constraints.providers,
            ownership: relay_constraints.ownership,
            endpoint_matcher: BridgeMatcher,
        }
    }
}

impl EndpointMatcher for BridgeMatcher {
    fn is_matching_relay(&self, relay: &Relay) -> bool {
        filter_bridge(relay)
    }

    // TODO(markus): Remove
    fn mullvad_endpoint(&self, _relay: &Relay) -> Option<MullvadEndpoint> {
        None
    }
}

// --- Define relay filters as simple functions / predicates ---
// The intent is to make it easier to re-use in iterator chains.

/// Returns whether `relay` is active.
pub const fn filter_on_active(relay: &Relay) -> bool {
    relay.active
}

/// Returns whether `relay` satisfy the location constraint posed by `filter`.
pub fn filter_on_location(filter: &Constraint<ResolvedLocationConstraint>, relay: &Relay) -> bool {
    let ignore_include_in_countries = true;
    filter.matches_with_opts(relay, ignore_include_in_countries)
}

/// Returns whether `relay` satisfy the ownership constraint posed by `filter`.
pub fn filter_on_ownership(filter: &Constraint<Ownership>, relay: &Relay) -> bool {
    filter.matches(relay)
}

/// Returns whether `relay` satisfy the providers constraint posed by `filter`.
pub fn filter_on_providers(filter: &Constraint<Providers>, relay: &Relay) -> bool {
    filter.matches(relay)
}

/// Returns whether the relay is an OpenVPN relay.
pub const fn filter_openvpn(relay: &Relay) -> bool {
    matches!(relay.endpoint_data, RelayEndpointData::Openvpn)
}

/// Returns whether the relay is a Wireguard relay.
pub const fn filter_wireguard(relay: &Relay) -> bool {
    matches!(relay.endpoint_data, RelayEndpointData::Wireguard(_))
}

/// Returns whether the relay is a bridge.
pub const fn filter_bridge(relay: &Relay) -> bool {
    matches!(relay.endpoint_data, RelayEndpointData::Bridge)
}

// --- OpenVPN specific filter ---

/// Returns wheter a relay (endpoint) satisfy the port constraints (transport protocol + port
/// number) posed by `filter`.
fn openvpn_filter_on_port(filter: OpenVpnConstraints, endpoint: &OpenVpnEndpointData) -> bool {
    let compatible_port =
        |transport_port: TransportPort, endpoint: &OpenVpnEndpoint| match transport_port.port {
            Constraint::Any => true,
            Constraint::Only(port) => port == endpoint.port,
        };

    match filter.port {
        Constraint::Any => true,
        Constraint::Only(transport_port) => endpoint
            .ports
            .iter()
            .filter(|endpoint| endpoint.protocol == transport_port.protocol)
            .any(|port| compatible_port(transport_port, port)),
    }
}

// --- Wireguard specific filter ---

/// Returns true if two relays are distinct from each other.
/// Returns false if they share the same hostname.
fn are_distinct_relays(peer: &Relay, relay: &Relay) -> bool {
    peer.hostname != relay.hostname
}

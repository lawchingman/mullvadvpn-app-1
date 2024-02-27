//! The implementation of the relay selector.

// TODO-list to refactor the relay selector once and for all.
// 1. Change the return type of `get_relay`
// The rationale here is that it really should be an enum to distinguish distinct cases.
//
// 2. Re-order to filtering code to a logical chain of filters.
// Today, it is very adhoc when certain functions filter on location data or
// relay-specific attributes. It woule make sense to process relay candidates
// based on one attribute at a time. Why not start with location to get it out
// of the way? With this, we could probably rip out location constraint data
// from OpenVpnMatcher and WireguardMatcher.
//
// 3. Try to propagate the RNG-bits to the top of the call stack, so that the
// core of the algorightm is pure/deterministic.
//
//
// X. Remove this TODO-list

mod helpers;
mod matcher;
#[cfg(test)]
mod tests;

use chrono::{DateTime, Local};
use ipnetwork::IpNetwork;
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::SystemTime,
};

use matcher::{BridgeMatcher, OpenVpnMatcher, RelayMatcher, WireguardMatcher};
use mullvad_types::{
    constraints::{Constraint, Intersection, Set},
    custom_list::CustomListsSettings,
    endpoint::{MullvadEndpoint, MullvadWireguardEndpoint},
    location::{Coordinates, Location},
    relay_constraints::{
        BridgeSettings, BridgeState, InternalBridgeConstraints, LocationConstraint,
        ObfuscationSettings, RelayConstraints, RelayConstraintsFormatter, RelayOverride,
        RelaySettings, ResolvedBridgeSettings, ResolvedLocationConstraint, TransportPort,
    },
    relay_list::{Relay, RelayList},
    settings::Settings,
    CustomTunnelEndpoint,
};
use talpid_types::{
    net::{
        obfuscation::ObfuscatorConfig, proxy::CustomProxy, wireguard, TransportProtocol, TunnelType,
    },
    ErrorExt,
};

use crate::constants::{MAX_BRIDGE_DISTANCE, MIN_BRIDGE_COUNT};
use crate::error::Error;
use crate::parsed_relays::ParsedRelays;

// TODO(markus): Where does this belong?
const DATE_TIME_FORMAT_STR: &str = "%Y-%m-%d %H:%M:%S%.3f";

#[derive(Clone)]
pub struct RelaySelector {
    config: Arc<Mutex<SelectorConfig>>,
    parsed_relays: Arc<Mutex<ParsedRelays>>,
    // strategy: Option<impl RelaySelectorStrategy> // <- Has to be a type paramter of `RelaySelector`
}

#[derive(Clone)]
pub struct SelectorConfig {
    pub relay_settings: RelaySettings,
    pub bridge_state: BridgeState,
    pub bridge_settings: BridgeSettings,
    pub obfuscation_settings: ObfuscationSettings,
    pub custom_lists: CustomListsSettings,
    pub relay_overrides: Vec<RelayOverride>,
}

impl Default for SelectorConfig {
    fn default() -> Self {
        let default_settings = Settings::default();
        SelectorConfig {
            relay_settings: default_settings.relay_settings,
            bridge_settings: default_settings.bridge_settings,
            obfuscation_settings: default_settings.obfuscation_settings,
            bridge_state: default_settings.bridge_state,
            custom_lists: default_settings.custom_lists,
            relay_overrides: default_settings.relay_overrides,
        }
    }
}

#[derive(Debug)]
pub enum SelectedBridge {
    Normal(NormalSelectedBridge),
    Custom(CustomProxy),
}

#[derive(Debug)]
pub struct NormalSelectedBridge {
    pub settings: CustomProxy,
    pub relay: Relay,
}

#[derive(Debug)]
pub enum SelectedRelay {
    Normal(NormalSelectedRelay),
    Custom(CustomTunnelEndpoint),
}

#[derive(Debug)]
pub struct NormalSelectedRelay {
    pub exit_relay: Relay,
    pub endpoint: MullvadEndpoint,
    pub entry_relay: Option<Relay>,
}

#[derive(Debug)]
pub struct SelectedObfuscator {
    pub config: ObfuscatorConfig,
    pub relay: Relay,
}

impl NormalSelectedRelay {
    const fn new(endpoint: MullvadEndpoint, exit_relay: Relay) -> Self {
        Self {
            exit_relay,
            endpoint,
            entry_relay: None,
        }
    }
}

#[derive(Clone)]
/// Define a strategy for the [`RelaySelector`] to use when deciding which relay
/// to return.
pub struct DefaultConstraints {
    /// This is the default constraints for tunnel endpoints. When the user
    /// hasn't selected any specific constraints, these constraints will take
    /// effect.
    ///
    /// # Note
    ///
    /// They are documented in further detail in `docs/relay-selector.md`.
    stratgegy: Vec<RelayConstraints>,
}

// TODO(markus): Remove this `allow`
#[allow(dead_code)]
impl DefaultConstraints {
    pub const fn new(initial_constraints: Vec<RelayConstraints>) -> DefaultConstraints {
        DefaultConstraints {
            stratgegy: initial_constraints,
        }
    }
}

trait RelaySelectorStrategy {
    /// TODO(markus): Document this
    fn resolve(&self, other: RelayConstraints, retry_attempt: usize) -> Option<RelayConstraints>;
    fn resolve_all(&self, other: RelayConstraints) -> impl Iterator<Item = RelayConstraints>;
}

impl RelaySelectorStrategy for DefaultConstraints {
    /// TODO(markus): Document this
    /// TODO(markus): Make more efficient
    fn resolve(&self, other: RelayConstraints, retry_attempt: usize) -> Option<RelayConstraints> {
        self.stratgegy
            .clone()
            .into_iter()
            .cycle()
            .filter_map(|constraint| constraint.intersection(other.clone()))
            .nth(retry_attempt)
    }

    fn resolve_all(&self, other: RelayConstraints) -> impl Iterator<Item = RelayConstraints> {
        self.stratgegy
            .clone()
            .into_iter()
            .cycle()
            .filter_map(move |constraint| constraint.intersection(other.clone()))
    }
}

impl RelaySelector {
    /// Returns a new `RelaySelector` backed by relays cached on disk.
    pub fn new(
        config: SelectorConfig,
        resource_path: impl AsRef<Path>,
        cache_path: impl AsRef<Path>,
    ) -> Self {
        let unsynchronized_parsed_relays =
            ParsedRelays::from_file(&cache_path, &resource_path, &config.relay_overrides)
                .unwrap_or_else(|error| {
                    log::error!(
                        "{}",
                        error.display_chain_with_msg("Unable to load cached and bundled relays")
                    );
                    ParsedRelays::empty()
                });
        log::info!(
            "Initialized with {} cached relays from {}",
            unsynchronized_parsed_relays.relays().count(),
            DateTime::<Local>::from(unsynchronized_parsed_relays.last_updated())
                .format(DATE_TIME_FORMAT_STR)
        );

        RelaySelector {
            config: Arc::new(Mutex::new(config)),
            parsed_relays: Arc::new(Mutex::new(unsynchronized_parsed_relays)),
        }
    }

    pub fn from_list(config: SelectorConfig, relay_list: RelayList) -> Self {
        RelaySelector {
            parsed_relays: Arc::new(Mutex::new(ParsedRelays::from_relay_list(
                relay_list,
                SystemTime::now(),
                &config.relay_overrides,
            ))),
            config: Arc::new(Mutex::new(config)),
        }
    }

    pub fn set_config(&mut self, config: SelectorConfig) {
        self.set_overrides(&config.relay_overrides);
        let mut config_mutex = self.config.lock().unwrap();
        *config_mutex = config;
    }

    pub fn set_relays(&self, relays: RelayList) {
        let mut parsed_relays = self.parsed_relays.lock().unwrap();
        parsed_relays.update(relays);
    }

    fn set_overrides(&mut self, relay_overrides: &[RelayOverride]) {
        let mut parsed_relays = self.parsed_relays.lock().unwrap();
        parsed_relays.set_overrides(relay_overrides);
    }

    /// Returns all countries and cities. The cities in the object returned does not have any
    /// relays in them.
    pub fn get_relays(&mut self) -> RelayList {
        let parsed_relays = self.parsed_relays.lock().unwrap();
        parsed_relays.original_list().clone()
    }

    pub fn etag(&self) -> Option<String> {
        self.parsed_relays.lock().unwrap().etag()
    }

    pub fn last_updated(&self) -> SystemTime {
        self.parsed_relays.lock().unwrap().last_updated()
    }

    /// Returns a non-custom bridge based on the relay and bridge constraints, ignoring the bridge
    /// state.
    pub fn get_bridge_forced(&self) -> Option<CustomProxy> {
        let parsed_relays = &self.parsed_relays.lock().unwrap();
        let config = self.config.lock().unwrap();
        let near_location = match &config.relay_settings {
            RelaySettings::Normal(settings) => {
                let custom_lists = { config.custom_lists.clone() };
                Self::get_relay_midpoint(parsed_relays, settings, &custom_lists)
            }
            _ => None,
        };
        let bridge_settings = &config.bridge_settings;
        let constraints = match bridge_settings.resolve() {
            Ok(ResolvedBridgeSettings::Normal(settings)) => InternalBridgeConstraints {
                location: settings.location.clone(),
                providers: settings.providers.clone(),
                ownership: settings.ownership,
                transport_protocol: Constraint::Only(TransportProtocol::Tcp),
            },
            _ => InternalBridgeConstraints {
                location: Constraint::Any,
                providers: Constraint::Any,
                ownership: Constraint::Any,
                transport_protocol: Constraint::Only(TransportProtocol::Tcp),
            },
        };

        let custom_lists = &config.custom_lists;
        Self::get_proxy_settings(parsed_relays, &constraints, near_location, custom_lists)
            .map(|(settings, _relay)| settings)
    }

    /// Returns a random relay and relay endpoint matching the current constraints.
    pub fn get_relay(
        &self,
        retry_attempt: u32,
    ) -> Result<
        (
            SelectedRelay,
            Option<SelectedBridge>,     // TODO(markus): OpenVPN
            Option<SelectedObfuscator>, // TODO(markus): Wireguard
        ),
        Error,
    > {
        let parsed_relays = &self.parsed_relays.lock().unwrap();
        let config = self.config.lock().unwrap();
        match &config.relay_settings {
            RelaySettings::CustomTunnelEndpoint(custom_relay) => {
                Ok((SelectedRelay::Custom(custom_relay.clone()), None, None))
            }
            RelaySettings::Normal(constraints) => {
                let relay = Self::get_tunnel_endpoint(
                    parsed_relays,
                    constraints,
                    config.bridge_state,
                    retry_attempt,
                    &config.custom_lists,
                )?;
                let bridge = match relay.endpoint {
                    MullvadEndpoint::OpenVpn(endpoint)
                        if endpoint.protocol == TransportProtocol::Tcp =>
                    {
                        let location = relay
                            .exit_relay
                            .location
                            .as_ref()
                            .expect("Relay has no location set");
                        Self::get_bridge_for(
                            parsed_relays,
                            &config,
                            location,
                            retry_attempt,
                            &config.custom_lists,
                        )?
                    }
                    _ => None,
                };
                let obfuscator = match relay.endpoint {
                    MullvadEndpoint::Wireguard(ref endpoint) => {
                        let obfuscator_relay =
                            relay.entry_relay.as_ref().unwrap_or(&relay.exit_relay);
                        let obfuscation_settings = &config.obfuscation_settings;
                        let udp2tcp_ports = {
                            let relay_list = parsed_relays.parsed_list();
                            relay_list.wireguard.udp2tcp_ports.clone()
                        };

                        helpers::get_obfuscator_inner(
                            &udp2tcp_ports,
                            obfuscation_settings,
                            obfuscator_relay,
                            endpoint,
                            retry_attempt,
                        )?
                    }
                    _ => None,
                };
                Ok((SelectedRelay::Normal(relay), bridge, obfuscator))
            }
        }
    }

    /// Returns a random relay and relay endpoint matching the given constraints and with
    /// preferences applied.
    #[cfg_attr(target_os = "android", allow(unused_variables))]
    fn get_tunnel_endpoint(
        parsed_relays: &ParsedRelays,
        relay_constraints: &RelayConstraints, // TODO(markus): This should be the intersection between user preferences and our defaults
        bridge_state: BridgeState,
        retry_attempt: u32,
        custom_lists: &CustomListsSettings,
    ) -> Result<NormalSelectedRelay, Error> {
        #[cfg(target_os = "android")]
        {
            self.get_wireguard_endpoint(relay_constraints, retry_attempt, custom_lists)
        }

        #[cfg(not(target_os = "android"))]
        match relay_constraints.tunnel_protocol {
            Constraint::Only(TunnelType::OpenVpn) => Self::get_openvpn_endpoint(
                parsed_relays,
                relay_constraints,
                bridge_state,
                retry_attempt,
                custom_lists,
            ),
            Constraint::Only(TunnelType::Wireguard) => Self::get_wireguard_endpoint(
                parsed_relays,
                relay_constraints,
                retry_attempt,
                custom_lists,
            ),
            Constraint::Any => Self::get_any_tunnel_endpoint(
                parsed_relays,
                relay_constraints,
                bridge_state,
                retry_attempt,
                custom_lists,
            ),
        }
    }

    // TODO(markus): This is used once .. Can it be decomposed?
    /// Returns the average location of relays that match the given constraints.
    /// This returns none if the location is `any` or if no relays match the constraints.
    fn get_relay_midpoint(
        parsed_relays: &ParsedRelays,
        relay_constraints: &RelayConstraints,
        custom_lists: &CustomListsSettings,
    ) -> Option<Coordinates> {
        if relay_constraints.location.is_any() {
            return None;
        }

        let (openvpn_data, wireguard_data) = (
            parsed_relays.parsed_list().openvpn.clone(),
            parsed_relays.parsed_list().wireguard.clone(),
        );

        let matcher = RelayMatcher::new(
            relay_constraints.clone(),
            openvpn_data,
            wireguard_data,
            custom_lists,
        );

        let mut matching_locations: Vec<Location> = {
            matcher
                .filter_matching_relay_list(parsed_relays.relays())
                .into_iter()
                .filter_map(|relay| relay.location)
                .collect()
        };
        matching_locations.dedup_by(|a, b| a.has_same_city(b));

        if matching_locations.is_empty() {
            return None;
        }
        Some(Coordinates::midpoint(&matching_locations))
    }

    /// Returns an OpenVpn endpoint, should only ever be used when the user has specified the tunnel
    /// protocol as only OpenVPN.
    #[cfg_attr(target_os = "android", allow(dead_code))]
    fn get_openvpn_endpoint(
        parsed_relays: &ParsedRelays,
        relay_constraints: &RelayConstraints, // TODO(markus): Only OpenVPN constraints
        bridge_state: BridgeState,
        retry_attempt: u32,
        custom_lists: &CustomListsSettings,
    ) -> Result<NormalSelectedRelay, Error> {
        let mut relay_matcher = RelayMatcher {
            locations: ResolvedLocationConstraint::from_constraint(
                relay_constraints.location.clone(),
                custom_lists,
            ),
            providers: relay_constraints.providers.clone(),
            ownership: relay_constraints.ownership,
            endpoint_matcher: OpenVpnMatcher::new(
                relay_constraints.openvpn_constraints,
                parsed_relays.parsed_list().openvpn.clone(),
            ),
        };

        if relay_matcher.endpoint_matcher.constraints.port.is_any()
            && bridge_state == BridgeState::On
        {
            relay_matcher.endpoint_matcher.constraints.port = Constraint::Only(TransportPort {
                protocol: TransportProtocol::Tcp,
                port: Constraint::Any,
            });

            // TODO(markus): Do I need to `collect` here?
            let relays: Vec<Relay> = parsed_relays.relays().cloned().collect();
            return helpers::get_tunnel_endpoint_internal(&relays, &relay_matcher);
        }

        let mut preferred_relay_matcher = relay_matcher.clone();

        let (preferred_port, preferred_protocol) =
            helpers::preferred_openvpn_constraints(retry_attempt);
        let should_try_preferred =
            match &mut preferred_relay_matcher.endpoint_matcher.constraints.port {
                // TODO(markus): Wow! An `@` sigil!
                any @ Constraint::Any => {
                    *any = Constraint::Only(TransportPort {
                        protocol: preferred_protocol,
                        port: preferred_port,
                    });
                    true
                }
                Constraint::Only(ref mut port_constraints)
                    if port_constraints.protocol == preferred_protocol
                        && port_constraints.port.is_any() =>
                {
                    port_constraints.port = preferred_port;
                    true
                }
                _ => false,
            };

        // TODO(markus): Do I really need to collect here?
        let relays: Vec<Relay> = parsed_relays.relays().cloned().collect();

        if should_try_preferred {
            helpers::get_tunnel_endpoint_internal(&relays, &preferred_relay_matcher)
                .or_else(|_| helpers::get_tunnel_endpoint_internal(&relays, &relay_matcher))
        } else {
            helpers::get_tunnel_endpoint_internal(&relays, &relay_matcher)
        }
    }

    fn get_wireguard_multi_hop_endpoint(
        parsed_relays: &ParsedRelays,
        mut entry_matcher: RelayMatcher<WireguardMatcher>,
        exit_locations: Constraint<LocationConstraint>,
        custom_lists: &CustomListsSettings,
    ) -> Result<NormalSelectedRelay, Error> {
        let relays: Vec<Relay> = parsed_relays.relays().cloned().collect();
        let wg = parsed_relays.parsed_list().wireguard.clone();
        let mut exit_matcher = RelayMatcher {
            locations: ResolvedLocationConstraint::from_constraint(exit_locations, custom_lists),
            providers: entry_matcher.providers.clone(),
            ownership: entry_matcher.ownership,
            endpoint_matcher: helpers::wireguard_exit_matcher(wg),
        };

        let (exit_relay, entry_relay, exit_endpoint, mut entry_endpoint) =
            if entry_matcher.locations.is_subset(&exit_matcher.locations) {
                let (entry_relay, entry_endpoint) =
                    Self::get_entry_endpoint(parsed_relays, &entry_matcher)?;
                exit_matcher.set_peer(entry_relay.clone());

                let exit_result = helpers::get_tunnel_endpoint_internal(&relays, &exit_matcher)?;
                (
                    exit_result.exit_relay,
                    entry_relay,
                    exit_result.endpoint,
                    entry_endpoint,
                )
            } else {
                let exit_result = helpers::get_tunnel_endpoint_internal(&relays, &exit_matcher)?;

                entry_matcher.set_peer(exit_result.exit_relay.clone());
                let (entry_relay, entry_endpoint) =
                    Self::get_entry_endpoint(parsed_relays, &entry_matcher)?;
                (
                    exit_result.exit_relay,
                    entry_relay,
                    exit_result.endpoint,
                    entry_endpoint,
                )
            };

        Self::set_entry_peers(&exit_endpoint.unwrap_wireguard().peer, &mut entry_endpoint);

        log::info!(
            "Selected entry relay {} at {} going through {} at {}",
            entry_relay.hostname,
            entry_endpoint.peer.endpoint.ip(),
            exit_relay.hostname,
            exit_endpoint.to_endpoint().address.ip(),
        );
        let result = {
            let endpoint = MullvadEndpoint::Wireguard(entry_endpoint);
            let entry_relay = Some(entry_relay);
            NormalSelectedRelay {
                exit_relay,
                endpoint,
                entry_relay,
            }
        };
        Ok(result)
    }

    /// Returns a WireGuard endpoint, should only ever be used when the user has specified the
    /// tunnel protocol as only WireGuard.
    fn get_wireguard_endpoint(
        parsed_relays: &ParsedRelays,
        relay_constraints: &RelayConstraints, // TODO(markus): Only Wireguard constraints
        retry_attempt: u32,
        custom_lists: &CustomListsSettings,
    ) -> Result<NormalSelectedRelay, Error> {
        let wg_endpoint_data = parsed_relays.parsed_list().wireguard.clone();

        // NOTE: If not using multihop then `location` is set as the only location constraint.
        // If using multihop then location is the exit constraint and
        // `wireguard_constraints.entry_location` is set as the entry location constraint.
        if !relay_constraints.wireguard_constraints.multihop() {
            let relays: Vec<Relay> = parsed_relays.relays().cloned().collect();
            let relay_matcher = RelayMatcher {
                locations: ResolvedLocationConstraint::from_constraint(
                    relay_constraints.location.clone(),
                    custom_lists,
                ),
                providers: relay_constraints.providers.clone(),
                ownership: relay_constraints.ownership,
                endpoint_matcher: WireguardMatcher::new(
                    relay_constraints.wireguard_constraints.clone(),
                    wg_endpoint_data,
                ),
            };

            let mut preferred_matcher: RelayMatcher<WireguardMatcher> = relay_matcher.clone();
            preferred_matcher.endpoint_matcher.port = preferred_matcher
                .endpoint_matcher
                .port
                .or(helpers::preferred_wireguard_port(retry_attempt));

            helpers::get_tunnel_endpoint_internal(&relays, &preferred_matcher)
                .or_else(|_| helpers::get_tunnel_endpoint_internal(&relays, &relay_matcher))
        } else {
            let mut entry_relay_matcher = RelayMatcher {
                locations: ResolvedLocationConstraint::from_constraint(
                    relay_constraints
                        .wireguard_constraints
                        .entry_location
                        .clone(),
                    custom_lists,
                ),
                providers: relay_constraints.providers.clone(),
                ownership: relay_constraints.ownership,
                endpoint_matcher: WireguardMatcher::new(
                    relay_constraints.wireguard_constraints.clone(),
                    wg_endpoint_data,
                ),
            };
            entry_relay_matcher.endpoint_matcher.port = entry_relay_matcher
                .endpoint_matcher
                .port
                .or(helpers::preferred_wireguard_port(retry_attempt));

            Self::get_wireguard_multi_hop_endpoint(
                parsed_relays,
                entry_relay_matcher,
                relay_constraints.location.clone(),
                custom_lists,
            )
        }
    }

    /// Like [Self::get_tunnel_endpoint_internal] but also selects an entry endpoint if applicable.
    #[cfg_attr(target_os = "android", allow(dead_code))]
    fn get_multihop_tunnel_endpoint_internal(
        parsed_relays: &ParsedRelays,
        relay_constraints: &RelayConstraints,
        custom_lists: &CustomListsSettings,
    ) -> Result<NormalSelectedRelay, Error> {
        let (openvpn_data, wireguard_data) = {
            (
                parsed_relays.parsed_list().openvpn.clone(),
                parsed_relays.parsed_list().wireguard.clone(),
            )
        };
        let mut matcher = RelayMatcher::new(
            relay_constraints.clone(),
            openvpn_data,
            wireguard_data.clone(),
            custom_lists,
        );

        let mut selected_entry_relay = None;
        let mut selected_entry_endpoint = None;
        let mut entry_matcher = RelayMatcher {
            locations: ResolvedLocationConstraint::from_constraint(
                relay_constraints
                    .wireguard_constraints
                    .entry_location
                    .clone(),
                custom_lists,
            ),
            providers: relay_constraints.providers.clone(),
            ownership: relay_constraints.ownership,
            endpoint_matcher: matcher.endpoint_matcher.clone(),
        }
        .into_wireguard_matcher();

        // Pick the entry relay first if its location constraint is a subset of the exit location.
        if relay_constraints.wireguard_constraints.multihop() {
            matcher.endpoint_matcher.wireguard = helpers::wireguard_exit_matcher(wireguard_data);
            if entry_matcher.locations.is_subset(&matcher.locations) {
                if let Ok((entry_relay, entry_endpoint)) =
                    Self::get_entry_endpoint(parsed_relays, &entry_matcher)
                {
                    matcher.endpoint_matcher.wireguard.peer = Some(entry_relay.clone());
                    selected_entry_relay = Some(entry_relay);
                    selected_entry_endpoint = Some(entry_endpoint);
                }
            }
        }

        // TODO(markus): Do I really need to collect here?
        let relays: Vec<Relay> = parsed_relays.relays().cloned().collect();
        let mut selected_relay = helpers::get_tunnel_endpoint_internal(&relays, &matcher)?;

        // Pick the entry relay last if its location constraint is NOT a subset of the exit
        // location.
        if matches!(selected_relay.endpoint, MullvadEndpoint::Wireguard(..))
            && relay_constraints.wireguard_constraints.multihop()
        {
            if !entry_matcher.locations.is_subset(&matcher.locations) {
                entry_matcher.endpoint_matcher.peer = Some(selected_relay.exit_relay.clone());
                if let Ok((entry_relay, entry_endpoint)) =
                    Self::get_entry_endpoint(parsed_relays, &entry_matcher)
                {
                    selected_entry_relay = Some(entry_relay);
                    selected_entry_endpoint = Some(entry_endpoint);
                }
            }

            match (selected_entry_endpoint, selected_entry_relay) {
                (Some(mut entry_endpoint), Some(entry_relay)) => {
                    Self::set_entry_peers(
                        &selected_relay.endpoint.unwrap_wireguard().peer,
                        &mut entry_endpoint,
                    );

                    log::info!(
                        "Selected entry relay {} at {} going through {} at {}",
                        entry_relay.hostname,
                        entry_endpoint.peer.endpoint.ip(),
                        selected_relay.exit_relay.hostname,
                        selected_relay.endpoint.to_endpoint().address.ip(),
                    );

                    selected_relay.endpoint = MullvadEndpoint::Wireguard(entry_endpoint);
                    selected_relay.entry_relay = Some(entry_relay);
                }
                _ => return Err(Error::NoRelay),
            }
        }

        Ok(selected_relay)
    }

    /// Returns a tunnel endpoint of any type, should only be used when the user hasn't specified a
    /// tunnel protocol.
    #[cfg_attr(target_os = "android", allow(dead_code))]
    fn get_any_tunnel_endpoint(
        parsed_relays: &ParsedRelays,
        relay_constraints: &RelayConstraints,
        bridge_state: BridgeState,
        retry_attempt: u32,
        custom_lists: &CustomListsSettings,
    ) -> Result<NormalSelectedRelay, Error> {
        let relays: Vec<Relay> = parsed_relays.relays().cloned().collect();
        let preferred_constraints = helpers::preferred_constraints(
            &relays,
            relay_constraints,
            bridge_state,
            retry_attempt,
            custom_lists,
        );

        if let Ok(result) = Self::get_multihop_tunnel_endpoint_internal(
            parsed_relays,
            &preferred_constraints,
            custom_lists,
        ) {
            log::debug!(
                "Relay matched on highest preference for retry attempt {}",
                retry_attempt
            );
            Ok(result)
        } else if let Ok(result) = Self::get_multihop_tunnel_endpoint_internal(
            parsed_relays,
            relay_constraints,
            custom_lists,
        ) {
            log::debug!(
                "Relay matched on second preference for retry attempt {}",
                retry_attempt
            );
            Ok(result)
        } else {
            log::warn!(
                "No relays matching constraints: {}",
                RelayConstraintsFormatter {
                    constraints: relay_constraints,
                    custom_lists,
                }
            );
            Err(Error::NoRelay)
        }
    }
    fn get_entry_endpoint(
        parsed_relays: &ParsedRelays,
        matcher: &RelayMatcher<WireguardMatcher>,
    ) -> Result<(Relay, MullvadWireguardEndpoint), Error> {
        let matching_relays: Vec<Relay> = matcher
            .filter_matching_relay_list(parsed_relays.relays())
            .into_iter()
            .collect();

        let relay = helpers::pick_random_relay(&matching_relays)
            .cloned()
            .ok_or(Error::NoRelay)?;
        let endpoint = matcher
            .mullvad_endpoint(&relay)
            .ok_or(Error::NoRelay)?
            .unwrap_wireguard()
            .clone();

        Ok((relay, endpoint))
    }

    fn set_entry_peers(
        exit_peer: &wireguard::PeerConfig,
        entry_endpoint: &mut MullvadWireguardEndpoint,
    ) {
        entry_endpoint.peer.allowed_ips = vec![IpNetwork::from(exit_peer.endpoint.ip())];
        entry_endpoint.exit_peer = Some(exit_peer.clone());
    }

    // TODO(markus): Decompose this function
    fn get_bridge_for(
        parsed_relays: &ParsedRelays,
        config: &SelectorConfig,
        location: &Location,
        retry_attempt: u32,
        custom_lists: &CustomListsSettings,
    ) -> Result<Option<SelectedBridge>, Error> {
        match config
            .bridge_settings
            .resolve()
            .map_err(Error::InvalidBridgeSettings)?
        {
            ResolvedBridgeSettings::Normal(settings) => {
                let bridge_constraints = InternalBridgeConstraints {
                    location: settings.location.clone(),
                    providers: settings.providers.clone(),
                    ownership: settings.ownership,
                    // FIXME: This is temporary while talpid-core only supports TCP proxies
                    transport_protocol: Constraint::Only(TransportProtocol::Tcp),
                };
                match config.bridge_state {
                    BridgeState::On => {
                        let (settings, relay) = Self::get_proxy_settings(
                            parsed_relays,
                            &bridge_constraints,
                            Some(location),
                            custom_lists,
                        )
                        .ok_or(Error::NoBridge)?;
                        Ok(Some(SelectedBridge::Normal(NormalSelectedBridge {
                            settings,
                            relay,
                        })))
                    }
                    BridgeState::Auto if helpers::should_use_bridge(retry_attempt) => {
                        Ok(Self::get_proxy_settings(
                            parsed_relays,
                            &bridge_constraints,
                            Some(location),
                            custom_lists,
                        )
                        .map(|(settings, relay)| {
                            SelectedBridge::Normal(NormalSelectedBridge { settings, relay })
                        }))
                    }
                    BridgeState::Auto | BridgeState::Off => Ok(None),
                }
            }
            ResolvedBridgeSettings::Custom(bridge_settings) => match config.bridge_state {
                BridgeState::On => Ok(Some(SelectedBridge::Custom(bridge_settings.clone()))),
                BridgeState::Auto if helpers::should_use_bridge(retry_attempt) => {
                    Ok(Some(SelectedBridge::Custom(bridge_settings.clone())))
                }
                BridgeState::Auto | BridgeState::Off => Ok(None),
            },
        }
    }

    // TODO(markus): Decompose this function!
    fn get_proxy_settings<T: Into<Coordinates>>(
        parsed_relays: &ParsedRelays,
        constraints: &InternalBridgeConstraints,
        location: Option<T>,
        custom_lists: &CustomListsSettings,
    ) -> Option<(CustomProxy, Relay)> {
        let matcher = RelayMatcher {
            locations: ResolvedLocationConstraint::from_constraint(
                constraints.location.clone(),
                custom_lists,
            ),
            providers: constraints.providers.clone(),
            ownership: constraints.ownership,
            endpoint_matcher: BridgeMatcher(()),
        };

        let matching_relays = matcher.filter_matching_relay_list(parsed_relays.relays());

        if matching_relays.is_empty() {
            return None;
        }

        let relay = if let Some(location) = location {
            let location = location.into();

            #[derive(Debug, Clone)]
            struct RelayWithDistance {
                relay: Relay,
                distance: f64,
            }

            let mut matching_relays: Vec<RelayWithDistance> = matching_relays
                .into_iter()
                .map(|relay| RelayWithDistance {
                    distance: relay.location.as_ref().unwrap().distance_from(&location),
                    relay,
                })
                .collect();
            matching_relays
                .sort_unstable_by_key(|relay: &RelayWithDistance| relay.distance as usize);

            let mut greatest_distance = 0f64;
            matching_relays = matching_relays
                .into_iter()
                .enumerate()
                .filter_map(|(i, relay)| {
                    if i < MIN_BRIDGE_COUNT || relay.distance <= MAX_BRIDGE_DISTANCE {
                        if relay.distance > greatest_distance {
                            greatest_distance = relay.distance;
                        }
                        return Some(relay);
                    }
                    None
                })
                .collect();

            let weight_fn =
                |relay: &RelayWithDistance| 1 + (greatest_distance - relay.distance) as u64;

            helpers::pick_random_relay_fn(&matching_relays, weight_fn)
                .cloned()
                .map(|relay_with_distance| relay_with_distance.relay)
        } else {
            helpers::pick_random_relay(&matching_relays).cloned()
        };
        relay.and_then(|relay| {
            let bridge = &parsed_relays.parsed_list().bridge;
            helpers::pick_random_bridge(bridge, &relay).map(|bridge| (bridge, relay.clone()))
        })
    }
}

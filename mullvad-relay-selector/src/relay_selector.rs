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
use once_cell::sync::Lazy;
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::SystemTime,
};

use matcher::{BridgeMatcher, OpenVpnMatcher, RelayMatcher, WireguardMatcher};
use mullvad_types::{
    constraints::{Constraint, Intersection, Set},
    custom_list::CustomListsSettings,
    endpoint::MullvadEndpoint,
    location::{Coordinates, Location},
    relay_constraints::{
        BridgeSettings, BridgeState, InternalBridgeConstraints, ObfuscationSettings,
        RelayConstraints, RelayOverride, RelaySettings, ResolvedBridgeSettings,
        ResolvedLocationConstraint, TransportPort,
    },
    relay_list::{Relay, RelayList},
    settings::Settings,
    CustomTunnelEndpoint,
};
use talpid_types::{
    net::{obfuscation::ObfuscatorConfig, proxy::CustomProxy, TransportProtocol, TunnelType},
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
    pub fn new() -> DefaultConstraints {
        use mullvad_types::relay_constraints::builder;
        // Define the order of constraints which we would like to try to apply
        // in successive retry attemps:
        // https://linear.app/mullvad/issue/DES-543/optimize-order-of-connection-parameters-when-trying-to-connect
        let default_constraints: Vec<RelayConstraints> = vec![
            // 1
            builder::wireguard::new().build(),
            // 2
            builder::wireguard::new().port(443).build(),
            // 3
            builder::wireguard::new()
                .ip_version(builder::wireguard::IpVersion::V6)
                .build(),
            // 4
            builder::openvpn::new()
                .transport_protocol(builder::openvpn::TransportProtocol::Tcp)
                .port(443)
                .build(),
            // 5 (UDP-over-TCP is not a relay constraint, but it is only available for Wireguard)
            builder::wireguard::new().build(),
            // 6 Same argument as in 5
            builder::wireguard::new()
                .ip_version(builder::wireguard::IpVersion::V6)
                .build(),
            // 7 Bridges is not a relay constraint
            builder::openvpn::new()
                .transport_protocol(builder::openvpn::TransportProtocol::Tcp)
                .build(),
        ];

        DefaultConstraints {
            stratgegy: default_constraints,
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
    #[allow(clippy::type_complexity)] // TODO(markus): Remove
    pub fn get_relay(
        &self,
        retry_attempt: usize,
    ) -> Result<
        (
            SelectedRelay,
            Option<SelectedBridge>,     // TODO(markus): OpenVPN
            Option<Relay>,              // TODO(markus): Wireguard
            Option<SelectedObfuscator>, // TODO(markus): Wireguard
        ),
        Error,
    > {
        let parsed_relays = &self.parsed_relays.lock().unwrap();
        let config = self.config.lock().unwrap();
        match &config.relay_settings {
            RelaySettings::CustomTunnelEndpoint(custom_relay) => Ok((
                SelectedRelay::Custom(custom_relay.clone()),
                None,
                None,
                None,
            )),
            RelaySettings::Normal(user_preferences) => {
                // Merge user preferences with the relay selector's default preferences.
                let strategy = DefaultConstraints::new();
                let constraints = strategy
                    .resolve(user_preferences.clone(), retry_attempt)
                    .unwrap_or(user_preferences.clone());
                let relay = Self::get_tunnel_endpoint(
                    parsed_relays,
                    &constraints,
                    config.bridge_state,
                    &config.custom_lists,
                )?;
                // OpenVPN-specific stuff
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
                // Wireguard-specific stuff
                // NOTE: If not using multihop then `location` is set as the only location constraint.
                // If using multihop then location is the exit constraint and
                // `wireguard_constraints.entry_location` is set as the entry location constraint.
                let entry_relay = match relay.endpoint {
                    MullvadEndpoint::Wireguard(_)
                        if constraints.wireguard_constraints.multihop() =>
                    {
                        // TODO(markus) This should be used to get a set of valid entry relays.
                        let entry_matcher = WireguardMatcher::new_entry_matcher(
                            constraints.clone(),
                            constraints.wireguard_constraints.clone(),
                            parsed_relays.parsed_list().wireguard.clone(),
                            &config.custom_lists,
                        );

                        // TODO(markus) This should be used to get a set of valid entry relays.
                        let exit_matcher = WireguardMatcher::new_exit_matcher(
                            constraints.clone(),
                            constraints.wireguard_constraints.clone(),
                            parsed_relays.parsed_list().wireguard.clone(),
                            &config.custom_lists,
                        );

                        Self::get_wireguard_multihop_endpoint(
                            parsed_relays,
                            entry_matcher,
                            exit_matcher,
                        )
                        .ok()
                        .as_ref()
                        .and_then(|relays| helpers::pick_random_relay(relays))
                        .cloned()
                    }
                    _ => None,
                };
                // Wireguard-specific stuff
                let obfuscator = match relay.endpoint {
                    MullvadEndpoint::Wireguard(ref endpoint) => {
                        let obfuscator_relay =
                            entry_relay.clone().unwrap_or(relay.exit_relay.clone());
                        let obfuscation_settings = &config.obfuscation_settings;
                        let udp2tcp_ports = {
                            let relay_list = parsed_relays.parsed_list();
                            relay_list.wireguard.udp2tcp_ports.clone()
                        };

                        helpers::get_obfuscator_inner(
                            &udp2tcp_ports,
                            obfuscation_settings,
                            &obfuscator_relay,
                            endpoint,
                            retry_attempt,
                        )?
                    }
                    _ => None,
                };
                Ok((
                    SelectedRelay::Normal(relay),
                    bridge,
                    entry_relay,
                    obfuscator,
                ))
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
        custom_lists: &CustomListsSettings,
    ) -> Result<NormalSelectedRelay, Error> {
        #[cfg(target_os = "android")]
        {
            let matcher = WireguardMatcher::new_matcher(
                relay_constraints.clone(),
                relay_constraints.wireguard_constraints.clone(),
                parsed_relays.parsed_list().wireguard.clone(),
                custom_lists,
            );

            helpers::get_tunnel_endpoint_internal(&relays, &matcher)
        }
        #[cfg(not(target_os = "android"))]
        match relay_constraints.tunnel_protocol {
            Constraint::Only(TunnelType::OpenVpn) => {
                let mut matcher: RelayMatcher<OpenVpnMatcher> = OpenVpnMatcher::new_matcher(
                    relay_constraints.clone(),
                    relay_constraints.openvpn_constraints,
                    parsed_relays.parsed_list().openvpn.clone(),
                    custom_lists,
                );

                // TODO(markus): Is it really necessary to mutate the `relay_matcher` here?
                // Can't this be part of the matcher logic, or not at all?
                // TODO(markus): Ask David about this code
                if matcher.endpoint_matcher.constraints.port.is_any()
                    && bridge_state == BridgeState::On
                {
                    matcher.endpoint_matcher.constraints.port = Constraint::Only(TransportPort {
                        protocol: TransportProtocol::Tcp,
                        port: Constraint::Any,
                    });
                }

                helpers::get_tunnel_endpoint_internal(parsed_relays.relays(), &matcher)
            }
            Constraint::Only(TunnelType::Wireguard) => {
                let matcher = WireguardMatcher::new_matcher(
                    relay_constraints.clone(),
                    relay_constraints.wireguard_constraints.clone(),
                    parsed_relays.parsed_list().wireguard.clone(),
                    custom_lists,
                );

                helpers::get_tunnel_endpoint_internal(parsed_relays.relays(), &matcher)
            }
            Constraint::Any => {
                let matcher = RelayMatcher::new(
                    relay_constraints.clone(),
                    parsed_relays.parsed_list().openvpn.clone(),
                    parsed_relays.parsed_list().wireguard.clone(),
                    custom_lists,
                );
                helpers::get_tunnel_endpoint_internal(parsed_relays.relays(), &matcher)
            }
        }
    }

    // TODO(markus): Basically, this should not exist at all. It's job is to use
    // randomness to select one relay from a set of relays, setting different
    // entry/exit IPs as it goes.
    fn get_wireguard_multihop_endpoint(
        parsed_relays: &ParsedRelays,
        entry_matcher: RelayMatcher<WireguardMatcher>,
        mut exit_matcher: RelayMatcher<WireguardMatcher>,
    ) -> Result<Vec<Relay>, Error> {
        let entry_relays = entry_matcher.filter_matching_relay_list(parsed_relays.relays());

        if entry_matcher.locations.is_subset(&exit_matcher.locations) {
            let entry_relay = helpers::pick_random_relay(&entry_relays)
                .cloned()
                .ok_or(Error::NoRelay)?;
            exit_matcher.set_peer(entry_relay);
            Ok(exit_matcher.filter_matching_relay_list(parsed_relays.relays()))
        } else {
            let _exit_relays = exit_matcher.filter_matching_relay_list(parsed_relays.relays());

            Ok(entry_matcher.filter_matching_relay_list(parsed_relays.relays()))
        }
    }

    // TODO(markus): Decompose this function
    fn get_bridge_for(
        parsed_relays: &ParsedRelays,
        config: &SelectorConfig,
        location: &Location,
        retry_attempt: usize,
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
}

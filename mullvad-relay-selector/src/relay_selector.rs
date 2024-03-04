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

use matcher::{BridgeMatcher, RelayMatcher, WireguardMatcher};
use mullvad_types::{
    constraints::{Constraint, Intersection, Set},
    custom_list::CustomListsSettings,
    endpoint::MullvadEndpoint,
    location::{Coordinates, Location},
    relay_constraints::{
        BridgeSettings, BridgeSettingsFilter, BridgeState, InternalBridgeConstraints,
        ObfuscationSettings, OpenVpnConstraints, OpenVpnConstraintsFilter, RelayConstraints,
        RelayConstraintsFilter, RelayOverride, RelaySettings, ResolvedBridgeSettings,
        ResolvedLocationConstraint, WireguardConstraints, WireguardConstraintsFilter,
    },
    relay_list::{Relay, RelayList},
    settings::Settings,
    CustomTunnelEndpoint,
};
use talpid_types::{
    net::{obfuscation::ObfuscatorConfig, proxy::CustomProxy, TransportProtocol},
    ErrorExt,
};

use crate::constants::{MAX_BRIDGE_DISTANCE, MIN_BRIDGE_COUNT};
use crate::error::Error;
use crate::parsed_relays::ParsedRelays;

use self::matcher::{AnyTunnelMatcher, EndpointMatcher};

/// [`RETRY_ORDER`] defines the order of constraints which we would like to try to apply
/// in successive retry attempts: https://linear.app/mullvad/issue/DES-543/optimize-order-of-connection-parameters-when-trying-to-connect
static RETRY_ORDER: Lazy<Vec<RelayConstraintsFilter>> = Lazy::new(|| {
    use mullvad_types::relay_constraints::builder::{any, openvpn, wireguard};
    vec![
        // 0
        any().build(),
        // 1
        wireguard::new().build(),
        // 2
        wireguard::new().port(443).build(),
        // 3
        wireguard::new()
            .ip_version(wireguard::IpVersion::V6)
            .build(),
        // 4
        openvpn::new()
            .transport_protocol(openvpn::TransportProtocol::Tcp)
            .port(443)
            .build(),
        // 5
        wireguard::new().udp2tcp().build(),
        // 6
        wireguard::new()
            .udp2tcp()
            .ip_version(wireguard::IpVersion::V6)
            .build(),
        // 7
        openvpn::new()
            .transport_protocol(openvpn::TransportProtocol::Tcp)
            .bridge()
            .build(),
    ]
});

// TODO(markus): Where does this belong?
const DATE_TIME_FORMAT_STR: &str = "%Y-%m-%d %H:%M:%S%.3f";

#[derive(Clone)]
pub struct RelaySelector {
    config: Arc<Mutex<SelectorConfig>>,
    parsed_relays: Arc<Mutex<ParsedRelays>>,
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

// TODO(markus): Move this?
impl SelectorConfig {
    /// Map user settings to [`RelayConstraintsFilter`].
    fn blah(&self) -> RelayConstraintsFilter {
        // TODO(markus): Rename
        // TODO(markus): Document
        fn wg_constraints(
            wireguard_constraints: WireguardConstraints,
            obfuscation_settings: ObfuscationSettings,
        ) -> WireguardConstraintsFilter {
            let WireguardConstraints {
                port,
                ip_version,
                use_multihop,
                entry_location,
            } = wireguard_constraints;
            WireguardConstraintsFilter {
                port,
                ip_version,
                use_multihop,
                entry_location,
                obfuscation: obfuscation_settings.selected_obfuscation,
                udp2tcp_port: Constraint::Only(obfuscation_settings.udp2tcp.clone()),
            }
        }

        // TODO(markus): Rename
        // TODO(markus): Document
        fn ovpn_constraints(
            openvpn_constraints: OpenVpnConstraints,
            bridge_state: BridgeState,
            bridge_settings: BridgeSettings,
        ) -> OpenVpnConstraintsFilter {
            OpenVpnConstraintsFilter {
                port: openvpn_constraints.port,
                bridge_settings: match bridge_state {
                    BridgeState::On | BridgeState::Auto => match bridge_settings.bridge_type {
                        mullvad_types::relay_constraints::BridgeType::Normal => Constraint::Only(
                            BridgeSettingsFilter::Normal(bridge_settings.normal.clone()),
                        ),
                        mullvad_types::relay_constraints::BridgeType::Custom => Constraint::Only(
                            BridgeSettingsFilter::Custom(bridge_settings.custom.clone()),
                        ),
                    },
                    BridgeState::Off => Constraint::Only(BridgeSettingsFilter::Off),
                },
            }
        }

        match &self.relay_settings {
            RelaySettings::CustomTunnelEndpoint(_) => panic!("Honestly don't know what to do"),
            RelaySettings::Normal(relay_constraints) => {
                let wireguard_constraints = wg_constraints(
                    relay_constraints.wireguard_constraints.clone(),
                    self.obfuscation_settings.clone(),
                );
                let openvpn_constraints = ovpn_constraints(
                    relay_constraints.openvpn_constraints,
                    self.bridge_state,
                    self.bridge_settings.clone(),
                );
                RelayConstraintsFilter {
                    location: relay_constraints.location.clone(),
                    providers: relay_constraints.providers.clone(),
                    ownership: relay_constraints.ownership,
                    tunnel_protocol: relay_constraints.tunnel_protocol,
                    wireguard_constraints,
                    openvpn_constraints,
                }
            }
        }
    }
}

/// The return type of `get_relay`.
pub enum GetRelay {
    Wireguard {
        relay: NormalSelectedRelay,
        entry: Option<Relay>,
        obfuscator: Option<SelectedObfuscator>,
    },
    OpenVpn {
        relay: NormalSelectedRelay,
        bridge: Option<SelectedBridge>,
    },
    Custom(CustomTunnelEndpoint),
}

impl GetRelay {
    pub fn relay(&self) -> SelectedRelay {
        match self {
            GetRelay::Wireguard { relay, .. } | GetRelay::OpenVpn { relay, .. } => {
                SelectedRelay::Normal(relay.clone())
            }
            GetRelay::Custom(relay) => SelectedRelay::Custom(relay.clone()),
        }
    }
}

#[derive(Debug)]
pub enum SelectedBridge {
    Normal { settings: CustomProxy, relay: Relay },
    Custom(CustomProxy),
}

#[derive(Debug)]
pub enum SelectedRelay {
    Normal(NormalSelectedRelay),
    Custom(CustomTunnelEndpoint),
}

#[derive(Debug, Clone)]
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
                Self::get_relay_midpoint(parsed_relays, settings, &config)
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
    pub fn get_relay(&self, retry_attempt: usize) -> Result<GetRelay, Error> {
        let parsed_relays = &self.parsed_relays.lock().unwrap();
        let config = self.config.lock().unwrap();
        match &config.relay_settings {
            RelaySettings::CustomTunnelEndpoint(custom_relay) => {
                Ok(GetRelay::Custom(custom_relay.clone()))
            }
            RelaySettings::Normal(_) => {
                let user_preferences = config.blah();
                // Merge user preferences with the relay selector's default preferences.
                let _constraints = RETRY_ORDER
                    .clone()
                    .into_iter()
                    .cycle()
                    .filter_map(|constraint| constraint.intersection(user_preferences.clone()))
                    .nth(retry_attempt);
                // TODO(markus): Get rid of this
                let constraints = RelayConstraints::new();
                Self::get_normal_relay(parsed_relays, &config, &user_preferences, &constraints)
            }
        }
    }

    // TODO(markus): Document
    // TODO(markus): Justify
    fn get_normal_relay(
        parsed_relays: &ParsedRelays,
        config: &SelectorConfig,
        // TODO(markus): Use this argument!
        _user_preferences: &RelayConstraintsFilter,
        constraints: &RelayConstraints, // TODO(markus): Remove this argument
    ) -> Result<GetRelay, Error> {
        let relay = Self::get_normal_relay_inner(parsed_relays, config, constraints);
        match relay.endpoint {
            MullvadEndpoint::OpenVpn(endpoint) => {
                let bridge = helpers::should_use_bridge(config)
                    .then(|| Self::get_bridge(&relay, &endpoint.protocol, parsed_relays, config))
                    .transpose()?
                    .flatten();
                Ok(GetRelay::OpenVpn { relay, bridge })
            }
            MullvadEndpoint::Wireguard(ref endpoint) => {
                let entry = constraints
                    .wireguard_constraints
                    .multihop()
                    .then(|| {
                        Self::get_wireguard_entry_relay(
                            parsed_relays,
                            constraints,
                            &config.custom_lists,
                        )
                    })
                    .flatten();

                let obfuscator = {
                    let obfuscator_relay = entry.clone().unwrap_or(relay.exit_relay.clone());
                    let udp2tcp_ports = parsed_relays.parsed_list().wireguard.udp2tcp_ports.clone();

                    helpers::get_obfuscator_inner(
                        &udp2tcp_ports,
                        &config.obfuscation_settings,
                        &obfuscator_relay,
                        endpoint,
                        0, // TODO(markus): Get id of this! Should be defined by `user_preferences`.
                    )?
                };

                Ok(GetRelay::Wireguard {
                    relay,
                    entry,
                    obfuscator,
                })
            }
        }
    }

    /// Get a single relay matching `constraints`.
    fn get_normal_relay_inner(
        parsed_relays: &ParsedRelays,
        config: &SelectorConfig,
        constraints: &RelayConstraints,
    ) -> NormalSelectedRelay {
        // Filter among all valid relays
        let relays = Self::get_tunnel_endpoints(
            parsed_relays,
            constraints,
            config.bridge_state,
            &config.custom_lists,
        );
        // Pick one of the valid relays.
        let relay = helpers::pick_random_relay(&relays).unwrap().clone();
        let matcher = RelayMatcher::new(
            constraints.clone(),
            parsed_relays.parsed_list().openvpn.clone(),
            config.bridge_state,
            parsed_relays.parsed_list().wireguard.clone(),
            &config.custom_lists,
        );
        // Fill in the connection details of the chosen relay.
        matcher
            .endpoint_matcher
            .mullvad_endpoint(&relay)
            .map(|endpoint| NormalSelectedRelay::new(endpoint, relay.clone()))
            // TODO(markus): Do not unwrap!
            .unwrap()
    }

    /// Returns a random relay and relay endpoint matching the given constraints and with
    /// preferences applied.
    #[cfg(target_os = "android")]
    #[cfg_attr(target_os = "android", allow(unused_variables))]
    fn get_tunnel_endpoints(
        parsed_relays: &ParsedRelays,
        relay_constraints: &RelayConstraints, // TODO(markus): This should be the intersection between user preferences and our defaults
        bridge_state: BridgeState,
        custom_lists: &CustomListsSettings,
    ) -> Vec<Relay> {
        let relays = parsed_relays.relays();
        let matcher = WireguardMatcher::new_matcher(
            relay_constraints.clone(),
            relay_constraints.wireguard_constraints.clone(),
            parsed_relays.parsed_list().wireguard.clone(),
            custom_lists,
        );

        helpers::get_tunnel_endpoint_internal(&relays, &matcher)
    }

    #[cfg(not(target_os = "android"))]
    /// Returns a random relay and relay endpoint matching the given constraints and with
    /// preferences applied.
    fn get_tunnel_endpoints(
        parsed_relays: &ParsedRelays,
        relay_constraints: &RelayConstraints, // TODO(markus): This should be the intersection between user preferences and our defaults
        bridge_state: BridgeState,
        custom_lists: &CustomListsSettings,
    ) -> Vec<Relay> {
        let relays = parsed_relays.relays();
        let matcher = RelayMatcher::new(
            relay_constraints.clone(),
            parsed_relays.parsed_list().openvpn.clone(),
            bridge_state,
            parsed_relays.parsed_list().wireguard.clone(),
            custom_lists,
        );
        matcher.filter_matching_relay_list(relays)
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
            Ok(entry_matcher.filter_matching_relay_list(parsed_relays.relays()))
        }
    }

    /// NOTE: If not using multihop then `location` is set as the only location constraint.
    /// If using multihop then location is the exit constraint and
    /// `wireguard_constraints.entry_location` is set as the entry location constraint.
    fn get_wireguard_entry_relay(
        parsed_relays: &ParsedRelays,
        constraints: &RelayConstraints,
        custom_lists: &CustomListsSettings,
    ) -> Option<Relay> {
        // TODO(markus) This should be used to get a set of valid entry relays.
        let entry_matcher = WireguardMatcher::new_entry_matcher(
            constraints.clone(),
            constraints.wireguard_constraints.clone(),
            parsed_relays.parsed_list().wireguard.clone(),
            custom_lists,
        );

        // TODO(markus) This should be used to get a set of valid entry relays.
        let exit_matcher = WireguardMatcher::new_exit_matcher(
            constraints.clone(),
            constraints.wireguard_constraints.clone(),
            parsed_relays.parsed_list().wireguard.clone(),
            custom_lists,
        );

        Self::get_wireguard_multihop_endpoint(parsed_relays, entry_matcher, exit_matcher)
            .ok()
            .as_ref()
            .and_then(|relays| helpers::pick_random_relay(relays))
            .cloned()
    }

    /// TODO(markus): Document
    /// TODO(markus): Justify
    fn get_bridge(
        relay: &NormalSelectedRelay,
        protocol: &TransportProtocol,
        parsed_relays: &ParsedRelays,
        config: &SelectorConfig,
    ) -> Result<Option<SelectedBridge>, Error> {
        let bridge_settings = config
            .bridge_settings
            .resolve()
            .map_err(Error::InvalidBridgeSettings)?;

        match protocol {
            TransportProtocol::Udp => {
                log::error!("Can not use OpenVPN bridges over UDP");
                Err(Error::NoBridge)
            }
            TransportProtocol::Tcp => {
                let location = relay
                    .exit_relay
                    .location
                    .as_ref()
                    .expect("Relay has no location set");
                Ok(Self::get_bridge_for(
                    parsed_relays,
                    &bridge_settings,
                    location,
                    &config.custom_lists,
                ))
            }
        }
    }

    // TODO(markus): Decompose this function
    fn get_bridge_for(
        parsed_relays: &ParsedRelays,
        config: &ResolvedBridgeSettings<'_>,
        location: &Location,
        custom_lists: &CustomListsSettings,
    ) -> Option<SelectedBridge> {
        match *config {
            ResolvedBridgeSettings::Custom(settings) => {
                Some(SelectedBridge::Custom(settings.clone()))
            }
            ResolvedBridgeSettings::Normal(settings) => {
                let bridge_constraints = InternalBridgeConstraints {
                    location: settings.location.clone(),
                    providers: settings.providers.clone(),
                    ownership: settings.ownership,
                    // FIXME: This is temporary while talpid-core only supports TCP proxies
                    transport_protocol: Constraint::Only(TransportProtocol::Tcp),
                };

                Self::get_proxy_settings(
                    parsed_relays,
                    &bridge_constraints,
                    Some(location),
                    custom_lists,
                )
                .map(|(settings, relay)| SelectedBridge::Normal { settings, relay })
            }
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
    /// This returns `None` if the location is [`Constraint::Any`] or if no
    /// relays match the constraints.
    fn get_relay_midpoint(
        parsed_relays: &ParsedRelays,
        constraints: &RelayConstraints,
        config: &SelectorConfig,
    ) -> Option<Coordinates> {
        let (openvpn_data, wireguard_data) = (
            parsed_relays.parsed_list().openvpn.clone(),
            parsed_relays.parsed_list().wireguard.clone(),
        );

        let matcher = RelayMatcher::new(
            constraints.clone(),
            openvpn_data,
            config.bridge_state,
            wireguard_data,
            &config.custom_lists.clone(),
        );

        Self::get_relay_midpoint_inner(parsed_relays, constraints, matcher)
    }

    fn get_relay_midpoint_inner(
        parsed_relays: &ParsedRelays,
        constraints: &RelayConstraints,
        matcher: RelayMatcher<AnyTunnelMatcher>,
    ) -> Option<Coordinates> {
        if constraints.location.is_any() {
            return None;
        }

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

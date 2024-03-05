//! The implementation of the relay selector.

// TODO-list to refactor the relay selector once and for all.
// 1. DONE Change the return type of `get_relay`
// The rationale here is that it really should be an enum to distinguish distinct cases.
//
// 2. DONE Re-order to filtering code to a logical chain of filters.
// Today, it is very adhoc when certain functions filter on location data or
// relay-specific attributes. It woule make sense to process relay candidates
// based on one attribute at a time. Why not start with location to get it out
// of the way? With this, we could probably rip out location constraint data
// from OpenVpnMatcher and WireguardMatcher.
//
// 3. DONE Try to propagate the RNG-bits to the top of the call stack, so that the
// core of the algorightm is pure/deterministic.
//
// 4. Create a 'query' type/language. I think the smoothest way is to move the
//    `RelayConstraintBuilder` to the `mullvad-relay-selector` crate.
//
// 5. Write tests.
//
// 6. Create an `ARCHITECTURE.md`, isch. Something that describes how the relay selector works,
//    such that other people can read it and understand wtfrick is going on.
//
// X. Remove this TODO-list

mod helpers;
mod matcher;
#[cfg(test)]
mod tests;

use chrono::{DateTime, Local};
use itertools::Itertools;
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
    endpoint::{MullvadEndpoint, MullvadWireguardEndpoint},
    location::{Coordinates, Location},
    relay_constraints::{
        BridgeSettings, BridgeSettingsFilter, BridgeState, InternalBridgeConstraints,
        ObfuscationSettings, OpenVpnConstraints, OpenVpnConstraintsFilter, RelayConstraintsFilter,
        RelayOverride, RelaySettings, ResolvedBridgeSettings, SelectedObfuscation,
        WireguardConstraints, WireguardConstraintsFilter,
    },
    relay_list::{Relay, RelayList},
    settings::Settings,
    CustomTunnelEndpoint,
};
use talpid_types::{
    net::{obfuscation::ObfuscatorConfig, proxy::CustomProxy, TransportProtocol, TunnelType},
    ErrorExt,
};

use crate::error::Error;
use crate::parsed_relays::ParsedRelays;

use self::matcher::{AnyTunnelMatcher, RelayDetailer};

/// [`RETRY_ORDER`] defines an ordered set of relay parameters which the relay selector should prioritize on
/// successive connection attempts.
/// in successive retry attempts: https://linear.app/mullvad/issue/DES-543/optimize-order-of-connection-parameters-when-trying-to-connect
pub static RETRY_ORDER: Lazy<Vec<RelayConstraintsFilter>> = Lazy::new(|| {
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
#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
pub enum SelectedBridge {
    Normal { settings: CustomProxy, relay: Relay },
    Custom(CustomProxy),
}

#[derive(Clone, Debug)]
pub enum SelectedRelay {
    Normal(NormalSelectedRelay),
    Custom(CustomTunnelEndpoint),
}

#[derive(Clone, Debug)]
pub struct NormalSelectedRelay {
    pub exit_relay: Relay,
    pub endpoint: MullvadEndpoint,
}

#[derive(Clone, Debug)]
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
        const DATE_TIME_FORMAT_STR: &str = "%Y-%m-%d %H:%M:%S%.3f";
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
            RelaySettings::Normal(_) => {
                // TODO(markus): Find a way to go from `RelaySettings::Normal(settings) =>
                // RelayConstraintsFilter`.
                let user_preferences = config.blah();
                Self::get_relay_midpoint(parsed_relays, &user_preferences, &config)
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
        let config = self.config.lock().unwrap();
        match &config.relay_settings {
            RelaySettings::CustomTunnelEndpoint(custom_relay) => {
                Ok(GetRelay::Custom(custom_relay.clone()))
            }
            RelaySettings::Normal(_) => {
                let user_preferences = config.blah();
                drop(config); // TODO(markus): This is rather ugly!
                self.get_relay_by_query_and_blah(user_preferences, &RETRY_ORDER, retry_attempt)
            }
        }
    }

    /// Returns random relay and relay endpoint matching `query`.
    // TODO(markus): Rename, only used for testing.. For now
    pub(crate) fn get_relay_by_query_and_blah(
        &self,
        query: RelayConstraintsFilter,
        retry_order: &[RelayConstraintsFilter],
        retry_attempt: usize,
    ) -> Result<GetRelay, Error> {
        let parsed_relays = &self.parsed_relays.lock().unwrap();
        let config = self.config.lock().unwrap();
        // Merge user preferences with the relay selector's default preferences.
        let constraints = retry_order
            .iter()
            .cycle()
            .filter_map(|constraint| constraint.clone().intersection(query.clone()))
            .nth(retry_attempt)
            .unwrap();

        Self::get_normal_relay(parsed_relays, &config, &constraints)
    }

    /// Returns random relay and relay endpoint matching `query`.
    pub fn get_relay_by_query(&self, query: RelayConstraintsFilter) -> Result<GetRelay, Error> {
        let parsed_relays = &self.parsed_relays.lock().unwrap();
        let config = self.config.lock().unwrap();
        Self::get_normal_relay(parsed_relays, &config, &query)
    }

    // TODO(markus): Document
    // TODO(markus): Justify
    fn get_normal_relay(
        parsed_relays: &ParsedRelays,
        config: &SelectorConfig,
        constraints: &RelayConstraintsFilter,
    ) -> Result<GetRelay, Error> {
        match constraints.tunnel_protocol {
            Constraint::Only(TunnelType::Wireguard) => {
                // TODO(markus): This should really be:
                // (exit <- get_relay, entry <- get_relay(exit)) <|> (entry <- get_relay, exit <- get_relay(entry))
                //
                // Sometimes, exit is more specific than entry.
                // If the exit constraint is more specific than the entry constraint, we should
                // probably pick the exit relay first to not run out of candidates and vice versa.
                //
                // The only case that should not be supported is if entry.hostname = exit.hostname,
                // otherwise we should be able to resolve entry + exit.
                let relay = Self::get_normal_relay_inner(parsed_relays, config, constraints)
                    .ok_or(Error::NoRelay)?;

                let entry = constraints
                    .wireguard_constraints
                    .multihop()
                    .then(|| {
                        Self::get_wireguard_entry_relay(
                            relay.exit_relay.clone(),
                            parsed_relays,
                            constraints,
                            &config.custom_lists,
                        )
                    })
                    .transpose()?;

                let obfuscator = match relay.endpoint {
                    MullvadEndpoint::Wireguard(ref endpoint) => {
                        let obfuscator = {
                            let obfuscator_relay =
                                entry.clone().unwrap_or(relay.exit_relay.clone());
                            let udp2tcp_ports =
                                parsed_relays.parsed_list().wireguard.udp2tcp_ports.clone();

                            Self::get_obfuscator(
                                constraints,
                                &udp2tcp_ports,
                                &obfuscator_relay,
                                endpoint,
                            )
                        };
                        obfuscator
                    }
                    _ => None, // TODO(markus): Yuck.
                };

                Ok(GetRelay::Wireguard {
                    relay,
                    entry,
                    obfuscator,
                })
            }
            Constraint::Only(TunnelType::OpenVpn) => {
                let relay = Self::get_normal_relay_inner(parsed_relays, config, constraints)
                    .ok_or(Error::NoRelay)?;
                let bridge = match relay.endpoint {
                    MullvadEndpoint::OpenVpn(endpoint) => helpers::should_use_bridge(config)
                        .then(|| {
                            Self::get_bridge(&relay, &endpoint.protocol, parsed_relays, config)
                        })
                        .transpose()?
                        .flatten(),
                    _ => None, // TODO(markus): Yuck.
                };
                Ok(GetRelay::OpenVpn { relay, bridge })
            }
            // TODO(markus): Clean up
            Constraint::Any => {
                // Try Wireguard, then OpenVPN.
                for tunnel_type in [TunnelType::Wireguard, TunnelType::OpenVpn] {
                    let mut new_constraints = constraints.clone();
                    new_constraints.tunnel_protocol = Constraint::Only(tunnel_type);
                    // If a suitable relay is found, return it.
                    if let Ok(relay) =
                        Self::get_normal_relay(parsed_relays, config, &new_constraints)
                    {
                        return Ok(relay);
                    }
                }
                Err(Error::NoRelay)
            }
        }
    }

    /// Get a single relay matching `constraints`.
    fn get_normal_relay_inner(
        parsed_relays: &ParsedRelays,
        config: &SelectorConfig,
        constraints: &RelayConstraintsFilter,
    ) -> Option<NormalSelectedRelay> {
        // Filter among all valid relays
        let relays = Self::get_tunnel_endpoints(
            parsed_relays,
            constraints,
            config.bridge_state,
            &config.custom_lists,
        );
        // Pick one of the valid relays.
        let relay = helpers::pick_random_relay(&relays).cloned()?;
        // TODO(markus): Do not create an entire matcher, only create a `RelayDetailer`.
        let matcher = RelayMatcher::new(
            constraints.clone(),
            parsed_relays.parsed_list().openvpn.clone(),
            config.bridge_state,
            parsed_relays.parsed_list().wireguard.clone(),
            &config.custom_lists,
        );
        // Fill in the connection details of the chosen relay.
        // TODO(markus): Change name
        let filler = RelayDetailer::new(matcher.endpoint_matcher.clone());
        filler.fill_in_the_details(relay)
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
        relay_constraints: &RelayConstraintsFilter,
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

    /// TODO(markus): Document
    fn get_wireguard_multihop_endpoint(
        exit_relay: Relay,
        parsed_relays: &ParsedRelays,
        mut entry_matcher: RelayMatcher<WireguardMatcher>,
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
            entry_matcher.set_peer(exit_relay);
            Ok(entry_matcher.filter_matching_relay_list(parsed_relays.relays()))
        }
    }

    /// NOTE: If not using multihop then `location` is set as the only location constraint.
    /// If using multihop then location is the exit constraint and
    /// `wireguard_constraints.entry_location` is set as the entry location constraint.
    ///
    /// Returns an error if no matching relay is found, OR the constraints forces the entry
    /// relay to be the same as the exit relay.
    fn get_wireguard_entry_relay(
        exit_relay: Relay,
        parsed_relays: &ParsedRelays,
        constraints: &RelayConstraintsFilter,
        custom_lists: &CustomListsSettings,
    ) -> Result<Relay, Error> {
        // TODO(markus) This should be used to get a set of valid entry relays.
        let entry_matcher = WireguardMatcher::new_entry_matcher(
            constraints.clone(),
            parsed_relays.parsed_list().wireguard.clone(),
            custom_lists,
        );

        // TODO(markus) This should be used to get a set of valid entry relays.
        let exit_matcher = WireguardMatcher::new_exit_matcher(
            constraints.clone(),
            parsed_relays.parsed_list().wireguard.clone(),
            custom_lists,
        );

        let candidates = Self::get_wireguard_multihop_endpoint(
            exit_relay,
            parsed_relays,
            entry_matcher,
            exit_matcher,
        )?;

        helpers::pick_random_relay(&candidates)
            .ok_or(Error::NoRelay)
            .cloned()
    }

    pub fn get_obfuscator(
        query: &RelayConstraintsFilter,
        udp2tcp_ports: &[u16],
        relay: &Relay,
        endpoint: &MullvadWireguardEndpoint,
    ) -> Option<SelectedObfuscator> {
        match query.wireguard_constraints.obfuscation {
            SelectedObfuscation::Off | SelectedObfuscation::Auto => None,
            SelectedObfuscation::Udp2Tcp => helpers::get_udp2tcp_obfuscator(
                &query.wireguard_constraints.udp2tcp_port,
                udp2tcp_ports,
                relay.clone(),
                endpoint,
            ),
        }
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

    /// Try to get a bridge that matches the given `constraints`.
    ///
    /// The connection details are returned alongside the relay hosting the bridge.
    fn get_proxy_settings<T: Into<Coordinates>>(
        parsed_relays: &ParsedRelays,
        constraints: &InternalBridgeConstraints,
        location: Option<T>,
        custom_lists: &CustomListsSettings,
    ) -> Option<(CustomProxy, Relay)> {
        let matcher = BridgeMatcher::new_matcher(constraints.clone(), custom_lists);
        let relays = matcher.filter_matching_relay_list(parsed_relays.relays());

        let relay = match location {
            Some(location) => Self::get_proximate_bridge(relays, location),
            None => helpers::pick_random_relay(&relays).cloned(),
        }?;

        let bridge = &parsed_relays.parsed_list().bridge;
        helpers::pick_random_bridge(bridge, &relay).map(|bridge| (bridge, relay.clone()))
    }

    /// Try to get a bridge which is close to `location`.
    fn get_proximate_bridge<T: Into<Coordinates>>(
        relays: Vec<Relay>,
        location: T,
    ) -> Option<Relay> {
        /// Minimum number of bridges to keep for selection when filtering by distance.
        const MIN_BRIDGE_COUNT: usize = 5;
        /// Max distance of bridges to consider for selection (km).
        const MAX_BRIDGE_DISTANCE: f64 = 1500f64;
        let location = location.into();

        #[derive(Debug, Clone)]
        struct RelayWithDistance {
            relay: Relay,
            distance: f64,
        }

        // Filter out all candidate bridges.
        let matching_relays: Vec<RelayWithDistance> = relays
            .into_iter()
            .map(|relay| RelayWithDistance {
                distance: relay.location.as_ref().unwrap().distance_from(&location),
                relay,
            })
            .sorted_unstable_by_key(|relay| relay.distance as usize)
            .take(MIN_BRIDGE_COUNT)
            .filter(|relay| relay.distance <= MAX_BRIDGE_DISTANCE)
            .collect();

        // Calculate the maximum distance from `location` among the candidates.
        let greatest_distance: f64 = matching_relays
            .iter()
            .map(|relay| relay.distance)
            .reduce(f64::max)?;
        // Define the weight function to prioritize bridges which are closer to `location`.
        let weight_fn = |relay: &RelayWithDistance| 1 + (greatest_distance - relay.distance) as u64;

        helpers::pick_random_relay_fn(&matching_relays, weight_fn)
            .cloned()
            .map(|relay_with_distance| relay_with_distance.relay)
    }

    /// Returns the average location of relays that match the given constraints.
    /// This returns `None` if the location is [`Constraint::Any`] or if no
    /// relays match the constraints.
    fn get_relay_midpoint(
        parsed_relays: &ParsedRelays,
        constraints: &RelayConstraintsFilter,
        config: &SelectorConfig,
    ) -> Option<Coordinates> {
        if constraints.location.is_any() {
            return None;
        }
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

        Self::get_relay_midpoint_inner(parsed_relays, matcher)
    }

    fn get_relay_midpoint_inner(
        parsed_relays: &ParsedRelays,
        matcher: RelayMatcher<AnyTunnelMatcher>,
    ) -> Option<Coordinates> {
        use std::ops::Not;
        let matching_locations: Vec<Location> = matcher
            .filter_matching_relay_list(parsed_relays.relays())
            .into_iter()
            .filter_map(|relay| relay.location)
            .unique_by(|location| location.city.clone())
            .collect();

        matching_locations
            .is_empty()
            .not()
            .then(|| Coordinates::midpoint(&matching_locations))
    }
}

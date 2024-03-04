//! Tests for verifying that the relay selector works as expected.
#![allow(unused)]

use mullvad_types::{
    constraints::Constraint,
    custom_list::CustomListsSettings,
    endpoint::{MullvadEndpoint, MullvadWireguardEndpoint},
    relay_constraints::{
        BridgeState, GeographicLocationConstraint, LocationConstraint, ObfuscationSettings,
        OpenVpnConstraints, Ownership, Providers, RelayConstraints, RelaySettings,
        SelectedObfuscation, TransportPort, WireguardConstraints,
    },
    relay_list::{
        BridgeEndpointData, OpenVpnEndpoint, OpenVpnEndpointData, Relay, RelayEndpointData,
        RelayList, RelayListCity, RelayListCountry, ShadowsocksEndpointData, WireguardEndpointData,
        WireguardRelayEndpointData,
    },
};
use once_cell::sync::Lazy;
use std::collections::HashSet;
use talpid_types::net::{
    obfuscation::ObfuscatorConfig, wireguard::PublicKey, Endpoint, TransportProtocol, TunnelType,
};

use crate::{
    error::Error,
    relay_selector::helpers,
    relay_selector::{NormalSelectedRelay, RelaySelector, SelectedRelay, SelectorConfig},
};

use super::SelectedObfuscator;

impl RelaySelector {
    fn get_obfuscator(
        &self,
        relay: &Relay,
        endpoint: &MullvadWireguardEndpoint,
        retry_attempt: usize,
    ) -> Result<Option<SelectedObfuscator>, Error> {
        // TODO(markus): Beware of deadlocks
        let config_mutex = self.config.lock().unwrap();
        let obfuscation_settings = &config_mutex.obfuscation_settings;
        let udp2tcp_ports = {
            &self
                .parsed_relays
                .lock()
                .unwrap()
                .parsed_list()
                .wireguard
                .udp2tcp_ports
                .clone()
        };

        helpers::get_obfuscator_inner(
            udp2tcp_ports,
            obfuscation_settings,
            relay,
            endpoint,
            retry_attempt,
        )
    }
}

static RELAYS: Lazy<RelayList> = Lazy::new(|| RelayList {
    etag: None,
    countries: vec![RelayListCountry {
        name: "Sweden".to_string(),
        code: "se".to_string(),
        cities: vec![RelayListCity {
            name: "Gothenburg".to_string(),
            code: "got".to_string(),
            latitude: 57.70887,
            longitude: 11.97456,
            relays: vec![
                Relay {
                    hostname: "se9-wireguard".to_string(),
                    ipv4_addr_in: "185.213.154.68".parse().unwrap(),
                    ipv6_addr_in: Some("2a03:1b20:5:f011::a09f".parse().unwrap()),
                    include_in_country: true,
                    active: true,
                    owned: true,
                    provider: "provider0".to_string(),
                    weight: 1,
                    endpoint_data: RelayEndpointData::Wireguard(WireguardRelayEndpointData {
                        public_key: PublicKey::from_base64(
                            "BLNHNoGO88LjV/wDBa7CUUwUzPq/fO2UwcGLy56hKy4=",
                        )
                        .unwrap(),
                    }),
                    location: None,
                },
                Relay {
                    hostname: "se10-wireguard".to_string(),
                    ipv4_addr_in: "185.213.154.69".parse().unwrap(),
                    ipv6_addr_in: Some("2a03:1b20:5:f011::a10f".parse().unwrap()),
                    include_in_country: true,
                    active: true,
                    owned: false,
                    provider: "provider1".to_string(),
                    weight: 1,
                    endpoint_data: RelayEndpointData::Wireguard(WireguardRelayEndpointData {
                        public_key: PublicKey::from_base64(
                            "BLNHNoGO88LjV/wDBa7CUUwUzPq/fO2UwcGLy56hKy4=",
                        )
                        .unwrap(),
                    }),
                    location: None,
                },
                Relay {
                    hostname: "se-got-001".to_string(),
                    ipv4_addr_in: "185.213.154.131".parse().unwrap(),
                    ipv6_addr_in: None,
                    include_in_country: true,
                    active: true,
                    owned: true,
                    provider: "provider2".to_string(),
                    weight: 1,
                    endpoint_data: RelayEndpointData::Openvpn,
                    location: None,
                },
                Relay {
                    hostname: "se-got-002".to_string(),
                    ipv4_addr_in: "1.2.3.4".parse().unwrap(),
                    ipv6_addr_in: None,
                    include_in_country: true,
                    active: true,
                    owned: true,
                    provider: "provider0".to_string(),
                    weight: 1,
                    endpoint_data: RelayEndpointData::Openvpn,
                    location: None,
                },
                Relay {
                    hostname: "se-got-br-001".to_string(),
                    ipv4_addr_in: "1.3.3.7".parse().unwrap(),
                    ipv6_addr_in: None,
                    include_in_country: true,
                    active: true,
                    owned: true,
                    provider: "provider3".to_string(),
                    weight: 1,
                    endpoint_data: RelayEndpointData::Bridge,
                    location: None,
                },
            ],
        }],
    }],
    openvpn: OpenVpnEndpointData {
        ports: vec![
            OpenVpnEndpoint {
                port: 1194,
                protocol: TransportProtocol::Udp,
            },
            OpenVpnEndpoint {
                port: 443,
                protocol: TransportProtocol::Tcp,
            },
            OpenVpnEndpoint {
                port: 80,
                protocol: TransportProtocol::Tcp,
            },
        ],
    },
    bridge: BridgeEndpointData {
        shadowsocks: vec![
            ShadowsocksEndpointData {
                port: 443,
                cipher: "aes-256-gcm".to_string(),
                password: "mullvad".to_string(),
                protocol: TransportProtocol::Tcp,
            },
            ShadowsocksEndpointData {
                port: 1234,
                cipher: "aes-256-cfb".to_string(),
                password: "mullvad".to_string(),
                protocol: TransportProtocol::Udp,
            },
            ShadowsocksEndpointData {
                port: 1236,
                cipher: "aes-256-gcm".to_string(),
                password: "mullvad".to_string(),
                protocol: TransportProtocol::Udp,
            },
        ],
    },
    wireguard: WireguardEndpointData {
        port_ranges: vec![(53, 53), (4000, 33433), (33565, 51820), (52000, 60000)],
        ipv4_gateway: "10.64.0.1".parse().unwrap(),
        ipv6_gateway: "fc00:bbbb:bbbb:bb01::1".parse().unwrap(),
        udp2tcp_ports: vec![],
    },
});

#[test]
fn test_preferred_tunnel_protocol() {
    // TODO(markus): Re write this test to not depend on the implementation of private functions on
    // the relay selector. In this case, it was `get_any_tunnel_endpoint`.

    // let relay_selector = RelaySelector::from_list(SelectorConfig::default(), RELAYS.clone());

    // // Prefer WG if the location only supports it
    // let location = GeographicLocationConstraint::Hostname(
    //     "se".to_string(),
    //     "got".to_string(),
    //     "se9-wireguard".to_string(),
    // );
    // let relay_constraints = RelayConstraints {
    //     location: Constraint::Only(LocationConstraint::from(location)),
    //     tunnel_protocol: Constraint::Any,
    //     ..RelayConstraints::default()
    // };

    // let preferred = {
    //     let parsed_relays = relay_selector.parsed_relays.lock().unwrap();
    //     let relays: Vec<Relay> = parsed_relays.relays().cloned().collect();
    //     helpers::preferred_constraints(
    //         &relays,
    //         &relay_constraints,
    //         BridgeState::Off,
    //         0,
    //         &CustomListsSettings::default(),
    //     )
    // };
    // assert_eq!(
    //     preferred.tunnel_protocol,
    //     Constraint::Only(TunnelType::Wireguard)
    // );

    // for attempt in 0..10 {
    //     // TODO(markus): Locking seems a bit weird here..
    //     let parsed_relays = relay_selector.parsed_relays.lock().unwrap();
    //     assert!(RelaySelector::get_any_tunnel_endpoint(
    //         &parsed_relays,
    //         &relay_constraints,
    //         BridgeState::Off,
    //         attempt,
    //         &CustomListsSettings::default()
    //     )
    //     .is_ok());
    // }

    // // Prefer OpenVPN if the location only supports it
    // let location = GeographicLocationConstraint::Hostname(
    //     "se".to_string(),
    //     "got".to_string(),
    //     "se-got-001".to_string(),
    // );
    // let relay_constraints = RelayConstraints {
    //     location: Constraint::Only(LocationConstraint::from(location)),
    //     tunnel_protocol: Constraint::Any,
    //     ..RelayConstraints::default()
    // };

    // let preferred = {
    //     let parsed_relays = relay_selector.parsed_relays.lock().unwrap();
    //     let relays: Vec<Relay> = parsed_relays.relays().cloned().collect();

    //     helpers::preferred_constraints(
    //         &relays,
    //         &relay_constraints,
    //         BridgeState::Off,
    //         0,
    //         &CustomListsSettings::default(),
    //     )
    // };
    // assert_eq!(
    //     preferred.tunnel_protocol,
    //     Constraint::Only(TunnelType::OpenVpn)
    // );

    // for attempt in 0..10 {
    //     // TODO(markus): Locking seems a bit weird here..
    //     let parsed_relays = relay_selector.parsed_relays.lock().unwrap();
    //     assert!(RelaySelector::get_any_tunnel_endpoint(
    //         &parsed_relays,
    //         &relay_constraints,
    //         BridgeState::Off,
    //         attempt,
    //         &CustomListsSettings::default()
    //     )
    //     .is_ok());
    // }
}

#[test]
fn test_wg_entry_hostname_collision() {
    // TODO(markus): Re write this test to not depend on the implementation of private functions on
    // the relay selector. In this case, it was `get_tunnel_endpoint`.

    // let relay_selector = RelaySelector::from_list(SelectorConfig::default(), RELAYS.clone());

    // let location1 = GeographicLocationConstraint::Hostname(
    //     "se".to_string(),
    //     "got".to_string(),
    //     "se9-wireguard".to_string(),
    // );
    // let location2 = GeographicLocationConstraint::Hostname(
    //     "se".to_string(),
    //     "got".to_string(),
    //     "se10-wireguard".to_string(),
    // );

    // let mut relay_constraints = RelayConstraints {
    //     location: Constraint::Only(LocationConstraint::from(location1.clone())),
    //     tunnel_protocol: Constraint::Only(TunnelType::Wireguard),
    //     ..RelayConstraints::default()
    // };

    // relay_constraints.wireguard_constraints.use_multihop(true);
    // relay_constraints.wireguard_constraints.entry_location =
    //     Constraint::Only(LocationConstraint::from(location1));

    // // The same host cannot be used for entry and exit

    // // TODO(markus): Locking seems a bit weird here..
    // let parsed_relays = relay_selector.parsed_relays.lock().unwrap();
    // assert!(RelaySelector::get_tunnel_endpoint(
    //     &parsed_relays,
    //     &relay_constraints,
    //     BridgeState::Off,
    //     // 0,
    //     &CustomListsSettings::default()
    // )
    // .is_err());

    // relay_constraints.wireguard_constraints.entry_location =
    //     Constraint::Only(LocationConstraint::from(location2));

    // // If the entry and exit differ, this should succeed

    // assert!(RelaySelector::get_tunnel_endpoint(
    //     &parsed_relays,
    //     &relay_constraints,
    //     BridgeState::Off,
    //     // 0,
    //     &CustomListsSettings::default()
    // )
    // .is_ok());
}

#[test]
fn test_wg_entry_filter() -> Result<(), String> {
    // TODO(markus): Re write this test to not depend on the implementation of private functions on
    // the relay selector. In this case, it was `get_tunnel_endpoint`.
    Ok(())
    // let relay_selector = RelaySelector::from_list(SelectorConfig::default(), RELAYS.clone());

    // let specific_hostname = "se10-wireguard";

    // let location_general = LocationConstraint::from(GeographicLocationConstraint::City(
    //     "se".to_string(),
    //     "got".to_string(),
    // ));
    // let location_specific = LocationConstraint::from(GeographicLocationConstraint::Hostname(
    //     "se".to_string(),
    //     "got".to_string(),
    //     specific_hostname.to_string(),
    // ));

    // let relay_constraints = relay_constraints::builder::wireguard::new()
    //     .location(location_general.clone())
    //     .multihop()
    //     .entry(location_specific.clone())
    //     .build();

    // // The exit must not equal the entry

    // {
    //     let parsed_relays = relay_selector.parsed_relays.lock().unwrap();
    //     let exit_relay = RelaySelector::get_tunnel_endpoint(
    //         &parsed_relays,
    //         &relay_constraints,
    //         BridgeState::Off,
    //         // 0,
    //         &CustomListsSettings::default(),
    //     )
    //     .map_err(|error| error.to_string())?
    //     .exit_relay;
    //     assert_ne!(exit_relay.hostname, specific_hostname);
    // }

    // let relay_constraints = relay_constraints::builder::wireguard::new()
    //     .location(location_specific.clone())
    //     .multihop()
    //     .entry(location_general.clone())
    //     .build();

    // // The entry must not equal the exit

    // let parsed_relays = relay_selector.parsed_relays.lock().unwrap();
    // let NormalSelectedRelay {
    //     exit_relay,
    //     endpoint,
    //     ..
    // } = RelaySelector::get_tunnel_endpoint(
    //     &parsed_relays,
    //     &relay_constraints,
    //     BridgeState::Off,
    //     // 0,
    //     &CustomListsSettings::default(),
    // )
    // .map_err(|error| error.to_string())?;

    // assert_eq!(exit_relay.hostname, specific_hostname);

    // let endpoint = endpoint.unwrap_wireguard();
    // assert_eq!(
    //     exit_relay.ipv4_addr_in,
    //     endpoint.exit_peer.as_ref().unwrap().endpoint.ip()
    // );
    // assert_ne!(exit_relay.ipv4_addr_in, endpoint.peer.endpoint.ip());

    // Ok(())
}

#[test]
fn test_openvpn_constraints() -> Result<(), String> {
    let relay_selector = RelaySelector::from_list(SelectorConfig::default(), RELAYS.clone());

    const ACTUAL_TCP_PORT: u16 = 443;
    const ACTUAL_UDP_PORT: u16 = 1194;
    const NON_EXISTENT_PORT: u16 = 1337;

    // Test all combinations of constraints, and whether they should
    // match some relay
    const CONSTRAINT_COMBINATIONS: [(OpenVpnConstraints, bool); 7] = [
        (
            OpenVpnConstraints {
                port: Constraint::Any,
            },
            true,
        ),
        (
            OpenVpnConstraints {
                port: Constraint::Only(TransportPort {
                    protocol: TransportProtocol::Udp,
                    port: Constraint::Any,
                }),
            },
            true,
        ),
        (
            OpenVpnConstraints {
                port: Constraint::Only(TransportPort {
                    protocol: TransportProtocol::Tcp,
                    port: Constraint::Any,
                }),
            },
            true,
        ),
        (
            OpenVpnConstraints {
                port: Constraint::Only(TransportPort {
                    protocol: TransportProtocol::Udp,
                    port: Constraint::Only(ACTUAL_UDP_PORT),
                }),
            },
            true,
        ),
        (
            OpenVpnConstraints {
                port: Constraint::Only(TransportPort {
                    protocol: TransportProtocol::Udp,
                    port: Constraint::Only(NON_EXISTENT_PORT),
                }),
            },
            false,
        ),
        (
            OpenVpnConstraints {
                port: Constraint::Only(TransportPort {
                    protocol: TransportProtocol::Tcp,
                    port: Constraint::Only(ACTUAL_TCP_PORT),
                }),
            },
            true,
        ),
        (
            OpenVpnConstraints {
                port: Constraint::Only(TransportPort {
                    protocol: TransportProtocol::Tcp,
                    port: Constraint::Only(NON_EXISTENT_PORT),
                }),
            },
            false,
        ),
    ];

    let matches_constraints =
        |endpoint: Endpoint, constraints: &OpenVpnConstraints| match constraints.port {
            Constraint::Any => true,
            Constraint::Only(TransportPort { protocol, port }) => {
                if endpoint.protocol != protocol {
                    return false;
                }
                match port {
                    Constraint::Any => true,
                    Constraint::Only(port) => port == endpoint.address.port(),
                }
            }
        };

    let mut relay_constraints = RelayConstraints {
        tunnel_protocol: Constraint::Only(TunnelType::OpenVpn),
        ..RelayConstraints::default()
    };

    for (openvpn_constraints, should_match) in &CONSTRAINT_COMBINATIONS {
        relay_constraints.openvpn_constraints = *openvpn_constraints;

        // TODO(markus): Re-write this block without calling `get_tunnel_endpoints`
        // for retry_attempt in 0..10 {
        //     // TODO(markus): Locking seems weird here
        //     let parsed_relays = relay_selector.parsed_relays.lock().unwrap();
        //     let relay = RelaySelector::get_tunnel_endpoints(
        //         &parsed_relays,
        //         &relay_constraints,
        //         BridgeState::Auto,
        //         // retry_attempt,
        //         &CustomListsSettings::default(),
        //     );

        //     println!("relay: {relay:?}, constraints: {relay_constraints:?}");

        //     if !should_match {
        //         relay.expect_err("unexpected relay");
        //         continue;
        //     }

        //     let relay = relay.expect("expected to find a relay");

        //     assert!(
        //             matches_constraints(
        //                 relay.endpoint.to_endpoint(),
        //                 &relay_constraints.openvpn_constraints,
        //             ),
        //             "{relay:?}, on attempt {retry_attempt}, did not match constraints: {relay_constraints:?}"
        //         );
        // }
    }

    Ok(())
}

#[test]
fn test_bridge_constraints() -> Result<(), String> {
    // TODO(markus): Re write this test to not depend on the implementation of private functions on
    // the relay selector. In this case, it was `preferred_constraints`.

    // let relay_selector = RelaySelector::from_list(SelectorConfig::default(), RELAYS.clone());
    // let location = LocationConstraint::from(GeographicLocationConstraint::Hostname(
    //     "se".to_string(),
    //     "got".to_string(),
    //     "se-got-001".to_string(),
    // ));
    // let mut relay_constraints = RelayConstraints {
    //     location: Constraint::Only(location),
    //     tunnel_protocol: Constraint::Any,
    //     ..RelayConstraints::default()
    // };
    // relay_constraints.openvpn_constraints.port = Constraint::Only(TransportPort {
    //     protocol: TransportProtocol::Udp,
    //     port: Constraint::Any,
    // });

    // let relays: Vec<Relay> = {
    //     let parsed_relays = relay_selector.parsed_relays.lock().unwrap();
    //     parsed_relays.relays().cloned().collect()
    // };

    // let preferred = helpers::preferred_constraints(
    //     &relays,
    //     &relay_constraints,
    //     BridgeState::On,
    //     0,
    //     &CustomListsSettings::default(),
    // );
    // assert_eq!(
    //     preferred.tunnel_protocol,
    //     Constraint::Only(TunnelType::OpenVpn)
    // );
    // // NOTE: TCP is preferred for bridges
    // assert_eq!(
    //     preferred.openvpn_constraints.port,
    //     Constraint::Only(TransportPort {
    //         protocol: TransportProtocol::Tcp,
    //         port: Constraint::Any,
    //     })
    // );

    // // Ignore bridge state where WireGuard is used
    // let location = LocationConstraint::from(GeographicLocationConstraint::Hostname(
    //     "se".to_string(),
    //     "got".to_string(),
    //     "se10-wireguard".to_string(),
    // ));
    // let relay_constraints = RelayConstraints {
    //     location: Constraint::Only(location),
    //     tunnel_protocol: Constraint::Any,
    //     ..RelayConstraints::default()
    // };
    // let preferred = helpers::preferred_constraints(
    //     &relays,
    //     &relay_constraints,
    //     BridgeState::On,
    //     0,
    //     &CustomListsSettings::default(),
    // );
    // assert_eq!(
    //     preferred.tunnel_protocol,
    //     Constraint::Only(TunnelType::Wireguard)
    // );

    // // Handle bridge setting when falling back on OpenVPN
    // let mut relay_constraints = RelayConstraints {
    //     location: Constraint::Any,
    //     tunnel_protocol: Constraint::Any,
    //     ..RelayConstraints::default()
    // };
    // relay_constraints.openvpn_constraints.port = Constraint::Only(TransportPort {
    //     protocol: TransportProtocol::Udp,
    //     port: Constraint::Any,
    // });
    // let preferred = helpers::preferred_constraints(
    //     &relays,
    //     &relay_constraints,
    //     BridgeState::On,
    //     0,
    //     &CustomListsSettings::default(),
    // );
    // assert_eq!(
    //     preferred.tunnel_protocol,
    //     Constraint::Only(TunnelType::Wireguard)
    // );
    // let preferred = helpers::preferred_constraints(
    //     &relays,
    //     &relay_constraints,
    //     BridgeState::On,
    //     3,
    //     &CustomListsSettings::default(),
    // );
    // assert_eq!(
    //     preferred.tunnel_protocol,
    //     Constraint::Only(TunnelType::OpenVpn)
    // );
    // assert_eq!(
    //     preferred.openvpn_constraints.port,
    //     Constraint::Only(TransportPort {
    //         protocol: TransportProtocol::Tcp,
    //         port: Constraint::Any,
    //     })
    // );

    Ok(())
}

#[test]
fn test_selecting_any_relay_will_consider_multihop() {
    // TODO(markus): Re write this test to not depend on the implementation of private functions on
    // the relay selector. In this case, it was `get_tunnel_endpoint`.
    //
    // let relay_constraints = RelayConstraints {
    //     wireguard_constraints: WireguardConstraints {
    //         use_multihop: Constraint::Only(true),
    //         ..WireguardConstraints::default()
    //     },
    //     // This has to be explicit otherwise Android will chose WireGuard when default
    //     // constructing.
    //     tunnel_protocol: Constraint::Any,
    //     ..RelayConstraints::default()
    // };

    // let relay_selector = RelaySelector::from_list(SelectorConfig::default(), RELAYS.clone());

    // let parsed_relays = relay_selector.parsed_relays.lock().unwrap();
    // let result = RelaySelector::get_tunnel_endpoint(
    //     &parsed_relays,
    //     &relay_constraints,
    //     BridgeState::Off,
    //     // 0,
    //     &CustomListsSettings::default(),
    // )
    // .expect(
    //     "Failed to get relay when tunnel constraints are set to Any and retrying the selection",
    // );

    // assert!(
    //     matches!(result.endpoint, MullvadEndpoint::Wireguard(_)) && result.entry_relay.is_some()
    // );
}

// const WIREGUARD_MULTIHOP_CONSTRAINTS: RelayConstraints = RelayConstraints {
//     location: Constraint::Any,
//     providers: Constraint::Any,
//     ownership: Constraint::Any,
//     wireguard_constraints: WireguardConstraints {
//         use_multihop: Constraint::Only(true),
//         port: Constraint::Any,
//         ip_version: Constraint::Any,
//         entry_location: Constraint::Any,
//     },
//     tunnel_protocol: Constraint::Only(TunnelType::Wireguard),
//     openvpn_constraints: OpenVpnConstraints {
//         port: Constraint::Any,
//     },
// };

const WIREGUARD_SINGLEHOP_CONSTRAINTS: RelayConstraints = RelayConstraints {
    location: Constraint::Any,
    providers: Constraint::Any,
    ownership: Constraint::Any,
    wireguard_constraints: WireguardConstraints {
        use_multihop: Constraint::Only(false),
        port: Constraint::Any,
        ip_version: Constraint::Any,
        entry_location: Constraint::Any,
    },
    tunnel_protocol: Constraint::Only(TunnelType::Wireguard),
    openvpn_constraints: OpenVpnConstraints {
        port: Constraint::Any,
    },
};

#[test]
fn test_selecting_wireguard_location_will_consider_multihop() {
    // TODO(markus): Re write this test to not depend on the implementation of private functions on
    // the relay selector. In this case, it was `get_tunnel_endpoint`.

    // let relay_selector = RelaySelector::from_list(SelectorConfig::default(), RELAYS.clone());
    // let parsed_relays = relay_selector.parsed_relays.lock().unwrap();

    // let result = RelaySelector::get_tunnel_endpoint(
    //     &parsed_relays,
    //     &WIREGUARD_MULTIHOP_CONSTRAINTS, BridgeState::Off,
    //     // 0,
    //     &CustomListsSettings::default(),
    // )
    //         .expect("Failed to get relay when tunnel constraints are set to default WireGuard multihop constraints");

    // assert!(result.entry_relay.is_some());
    // TODO: Verify that neither endpoint is using obfuscation for retry attempt 0
}

#[test]
fn test_selecting_wg_endpoint_with_udp2tcp_obfuscation() {
    // TODO: Re write this test to not depend on the implementation of private functions on
    // the relay selector. In this case, it was `get_tunnel_endpoint`.
    // let relay_selector = RelaySelector::from_list(SelectorConfig::default(), RELAYS.clone());
    // let result = {
    //     let parsed_relays = relay_selector.parsed_relays.lock().unwrap();

    //     let result = RelaySelector::get_tunnel_endpoints(
    //         &parsed_relays,
    //         &WIREGUARD_SINGLEHOP_CONSTRAINTS,
    //         BridgeState::Off,
    //         // 0,
    //         &CustomListsSettings::default(),
    //     )
    //     .expect(
    //         "Failed to get relay when tunnel constraints are set to default WireGuard constraints",
    //     );

    //     // assert!(result.entry_relay.is_none());
    //     assert!(matches!(result.endpoint, MullvadEndpoint::Wireguard { .. }));

    //     relay_selector.config.lock().unwrap().obfuscation_settings = ObfuscationSettings {
    //         selected_obfuscation: SelectedObfuscation::Udp2Tcp,
    //         ..ObfuscationSettings::default()
    //     };

    //     result
    // };

    // let obfs_config = relay_selector
    //     .get_obfuscator(&result.exit_relay, result.endpoint.unwrap_wireguard(), 0)
    //     .unwrap()
    //     .unwrap();

    // assert!(matches!(
    //     obfs_config,
    //     SelectedObfuscator {
    //         config: ObfuscatorConfig::Udp2Tcp { .. },
    //         ..
    //     }
    // ));
}

#[test]
fn test_selecting_wg_endpoint_with_auto_obfuscation() {
    // TODO: Re write this test to not depend on the implementation of private functions on
    // the relay selector. In this case, it was `get_tunnel_endpoint`.
    // let relay_selector = RelaySelector::from_list(SelectorConfig::default(), RELAYS.clone());
    // let result = {
    //     let parsed_relays = relay_selector.parsed_relays.lock().unwrap();

    //     let result = RelaySelector::get_tunnel_endpoint(
    //         &parsed_relays,
    //         &WIREGUARD_SINGLEHOP_CONSTRAINTS,
    //         BridgeState::Off,
    //         // 0,
    //         &CustomListsSettings::default(),
    //     )
    //     .expect(
    //         "Failed to get relay when tunnel constraints are set to default WireGuard constraints",
    //     );

    //     // assert!(result.entry_relay.is_none());
    //     assert!(matches!(result.endpoint, MullvadEndpoint::Wireguard { .. }));

    //     relay_selector.config.lock().unwrap().obfuscation_settings = ObfuscationSettings {
    //         selected_obfuscation: SelectedObfuscation::Auto,
    //         ..ObfuscationSettings::default()
    //     };

    //     result
    // };

    // assert!(relay_selector
    //     .get_obfuscator(&result.exit_relay, result.endpoint.unwrap_wireguard(), 0,)
    //     .unwrap()
    //     .is_none());

    // assert!(relay_selector
    //     .get_obfuscator(&result.exit_relay, result.endpoint.unwrap_wireguard(), 1,)
    //     .unwrap()
    //     .is_none());

    // assert!(relay_selector
    //     .get_obfuscator(&result.exit_relay, result.endpoint.unwrap_wireguard(), 2,)
    //     .unwrap()
    //     .is_some());
}

#[test]
fn test_selected_endpoints_use_correct_port_ranges() {
    // TODO: Re write this test to not depend on the implementation of private functions on
    // the relay selector. In this case, it was `get_tunnel_endpoint`.
    let relay_selector = RelaySelector::from_list(SelectorConfig::default(), RELAYS.clone());

    const TCP2UDP_PORTS: [u16; 3] = [80, 443, 5001];

    {
        relay_selector.config.lock().unwrap().obfuscation_settings = ObfuscationSettings {
            selected_obfuscation: SelectedObfuscation::Udp2Tcp,
            ..ObfuscationSettings::default()
        };
    }

    for attempt in 0..1000 {
        // let result = {
        //     // TODO(markus): It seems weird to lock here
        //     let parsed_relays = relay_selector.parsed_relays.lock().unwrap();
        //     RelaySelector::get_tunnel_endpoint(
        //         &parsed_relays,
        //         &WIREGUARD_SINGLEHOP_CONSTRAINTS,
        //         BridgeState::Off,
        //         // attempt,
        //         &CustomListsSettings::default(),
        //     )
        //     .expect("Failed to select a WireGuard relay")
        // };
        // // assert!(result.entry_relay.is_none());

        // let obfs_config = relay_selector
        //     .get_obfuscator(
        //         &result.exit_relay,
        //         result.endpoint.unwrap_wireguard(),
        //         attempt,
        //     )
        //     .unwrap()
        //     .expect("Failed to get Tcp2Udp endpoint");

        // assert!(matches!(
        //     obfs_config,
        //     SelectedObfuscator {
        //         config: ObfuscatorConfig::Udp2Tcp { .. },
        //         ..
        //     }
        // ));

        // let SelectedObfuscator {
        //     config: ObfuscatorConfig::Udp2Tcp { endpoint },
        //     ..
        // } = obfs_config;
        // assert!(TCP2UDP_PORTS.contains(&endpoint.port()));
    }
}

#[test]
fn test_ownership() {
    let relay_selector = RelaySelector::from_list(SelectorConfig::default(), RELAYS.clone());
    let parsed_relays = relay_selector.parsed_relays.lock().unwrap();
    let mut constraints = RelayConstraints::default();
    // for _attempt in 0..10 {
    //     constraints.ownership = Constraint::Only(Ownership::MullvadOwned);
    //     let relay = RelaySelector::get_tunnel_endpoint(
    //         &parsed_relays,
    //         &constraints,
    //         BridgeState::Auto,
    //         // attempt,
    //         &CustomListsSettings::default(),
    //     )
    //     .unwrap();
    //     assert!(matches!(
    //         relay,
    //         NormalSelectedRelay {
    //             exit_relay: Relay { owned: true, .. },
    //             ..
    //         }
    //     ));

    //     constraints.ownership = Constraint::Only(Ownership::Rented);
    //     let relay = RelaySelector::get_tunnel_endpoint(
    //         &parsed_relays,
    //         &constraints,
    //         BridgeState::Auto,
    //         // attempt,
    //         &CustomListsSettings::default(),
    //     )
    //     .unwrap();
    //     assert!(matches!(
    //         relay,
    //         NormalSelectedRelay {
    //             exit_relay: Relay { owned: false, .. },
    //             ..
    //         }
    //     ));
    // }
}

// Make sure server and port selection varies between retry attempts.
#[test]
fn test_load_balancing() {
    let relay_selector = RelaySelector::from_list(SelectorConfig::default(), RELAYS.clone());

    for tunnel_protocol in [
        Constraint::Any,
        Constraint::Only(TunnelType::Wireguard),
        Constraint::Only(TunnelType::OpenVpn),
    ] {
        {
            let mut config = relay_selector.config.lock().unwrap();
            config.relay_settings = RelaySettings::Normal(RelayConstraints {
                tunnel_protocol,
                location: Constraint::Only(LocationConstraint::from(
                    GeographicLocationConstraint::Country("se".to_string()),
                )),
                ..RelayConstraints::default()
            });
        }

        let mut actual_ports = HashSet::new();
        let mut actual_ips = HashSet::new();

        for retry_attempt in 0..30 {
            let relay = relay_selector.get_relay(retry_attempt).unwrap().relay();
            match relay {
                SelectedRelay::Normal(relay) => {
                    let address = relay.endpoint.to_endpoint().address;
                    actual_ports.insert(address.port());
                    actual_ips.insert(address.ip());
                }
                SelectedRelay::Custom(_) => unreachable!("not using custom relay"),
            }
        }

        assert!(
                actual_ports.len() > 1,
                "expected more than 1 port, got {actual_ports:?}, for tunnel protocol {tunnel_protocol:?}",
            );
        assert!(
                actual_ips.len() > 1,
                "expected more than 1 server, got {actual_ips:?}, for tunnel protocol {tunnel_protocol:?}",
            );
    }
}

#[test]
fn test_providers() {
    const EXPECTED_PROVIDERS: [&str; 2] = ["provider0", "provider2"];

    let relay_selector = RelaySelector::from_list(SelectorConfig::default(), RELAYS.clone());
    let parsed_relays = relay_selector.parsed_relays.lock().unwrap();
    let mut constraints = RelayConstraints::default();

    for _attempt in 0..10 {
        // constraints.providers = Constraint::Only(
        //     Providers::new(EXPECTED_PROVIDERS.into_iter().map(|p| p.to_owned())).unwrap(),
        // );
        // let relay = RelaySelector::get_tunnel_endpoint(
        //     &parsed_relays,
        //     &constraints,
        //     BridgeState::Auto,
        //     // attempt,
        //     &CustomListsSettings::default(),
        // )
        // .unwrap();
        // assert!(
        //     EXPECTED_PROVIDERS.contains(&relay.exit_relay.provider.as_str()),
        //     "cannot find provider {} in {:?}",
        //     relay.exit_relay.provider,
        //     EXPECTED_PROVIDERS
        // );
    }
}

/// Verify that bridges are automatically used when bridge mode is set
/// to automatic.
#[test]
fn test_auto_bridge() {
    // TODO(markus): Device a test that is not directly tied to the implementation of any function in the relay selector.
    // Maybe we should define a custom strategy to use for each test case?
}

/// Ensure that `include_in_country` is ignored if all relays have it set to false (i.e., some
/// relay is returned). Also ensure that `include_in_country` is respected if some relays
/// have it set to true (i.e., that relay is never returned)
#[test]
fn test_include_in_country() {
    let mut relay_list = RelayList {
        etag: None,
        countries: vec![RelayListCountry {
            name: "Sweden".to_string(),
            code: "se".to_string(),
            cities: vec![RelayListCity {
                name: "Gothenburg".to_string(),
                code: "got".to_string(),
                latitude: 57.70887,
                longitude: 11.97456,
                relays: vec![
                    Relay {
                        hostname: "se9-wireguard".to_string(),
                        ipv4_addr_in: "185.213.154.68".parse().unwrap(),
                        ipv6_addr_in: Some("2a03:1b20:5:f011::a09f".parse().unwrap()),
                        include_in_country: false,
                        active: true,
                        owned: true,
                        provider: "31173".to_string(),
                        weight: 1,
                        endpoint_data: RelayEndpointData::Wireguard(WireguardRelayEndpointData {
                            public_key: PublicKey::from_base64(
                                "BLNHNoGO88LjV/wDBa7CUUwUzPq/fO2UwcGLy56hKy4=",
                            )
                            .unwrap(),
                        }),
                        location: None,
                    },
                    Relay {
                        hostname: "se10-wireguard".to_string(),
                        ipv4_addr_in: "185.213.154.69".parse().unwrap(),
                        ipv6_addr_in: Some("2a03:1b20:5:f011::a10f".parse().unwrap()),
                        include_in_country: false,
                        active: true,
                        owned: false,
                        provider: "31173".to_string(),
                        weight: 1,
                        endpoint_data: RelayEndpointData::Wireguard(WireguardRelayEndpointData {
                            public_key: PublicKey::from_base64(
                                "BLNHNoGO88LjV/wDBa7CUUwUzPq/fO2UwcGLy56hKy4=",
                            )
                            .unwrap(),
                        }),
                        location: None,
                    },
                ],
            }],
        }],
        openvpn: OpenVpnEndpointData {
            ports: vec![
                OpenVpnEndpoint {
                    port: 1194,
                    protocol: TransportProtocol::Udp,
                },
                OpenVpnEndpoint {
                    port: 443,
                    protocol: TransportProtocol::Tcp,
                },
                OpenVpnEndpoint {
                    port: 80,
                    protocol: TransportProtocol::Tcp,
                },
            ],
        },
        bridge: BridgeEndpointData {
            shadowsocks: vec![],
        },
        wireguard: WireguardEndpointData {
            port_ranges: vec![(53, 53), (4000, 33433), (33565, 51820), (52000, 60000)],
            ipv4_gateway: "10.64.0.1".parse().unwrap(),
            ipv6_gateway: "fc00:bbbb:bbbb:bb01::1".parse().unwrap(),
            udp2tcp_ports: vec![],
        },
    };

    // If include_in_country is false for all relays, a relay must be selected anyway.
    //

    let relay_selector = RelaySelector::from_list(SelectorConfig::default(), relay_list.clone());
    assert!(relay_selector.get_relay(0).is_ok());

    // If include_in_country is true for some relay, it must always be selected.
    //

    relay_list.countries[0].cities[0].relays[0].include_in_country = true;
    let expected_hostname = relay_list.countries[0].cities[0].relays[0].hostname.clone();

    let relay_selector = RelaySelector::from_list(SelectorConfig::default(), relay_list);
    let relay = relay_selector.get_relay(0).expect("expected match").relay();

    assert!(
        matches!(
            relay,
            SelectedRelay::Normal(NormalSelectedRelay {
                exit_relay: Relay {
                    ref hostname,
                    ..
                },
                ..
            }) if hostname == &expected_hostname,
        ),
        "found {relay:?}, expected {expected_hostname:?}",
    )
}

/*
#[test]
fn test_new_merge_strategy() {
    // TODO(markus): Test a user preference such that it can not unify with any default constraint.
    // Then, we should check that `get_relay` uses the user preferences as is.

    // create an ordered collection of relay constraints to use when finding an appropriate relay
    let strategy = DefaultConstraints::new();

    // user_preferences is arbitrary, it could be anything
    let user_preferences: RelayConstraints = RelayConstraints::default();

    // 1
    let resolved_constraint = strategy.resolve(user_preferences.clone(), 0);
    assert_eq!(resolved_constraint, user_preferences.clone().into());
    // 2
    let resolved_constraint = strategy.resolve(user_preferences.clone(), 1);

    let mut c = user_preferences.clone();
    c.wireguard_constraints.port = Constraint::Only(443);
    assert_eq!(c, resolved_constraint.unwrap());
}
*/

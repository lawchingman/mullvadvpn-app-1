//! TODO(markus): Remove old test code/snippets/comments
//! Tests for verifying that the relay selector works as expected.
#![allow(unused)]

use mullvad_types::{
    constraints::Constraint,
    custom_list::CustomListsSettings,
    endpoint::{MullvadEndpoint, MullvadWireguardEndpoint},
    relay_constraints::{
        builder::{any, openvpn, wireguard},
        BridgeConstraints, BridgeSettingsFilter, BridgeState, GeographicLocationConstraint,
        LocationConstraint, ObfuscationSettings, OpenVpnConstraints, OpenVpnConstraintsFilter,
        Ownership, Providers, RelayConstraints, RelayConstraintsFilter, RelaySettings,
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
    relay_selector::{
        helpers::{self, should_use_bridge},
        matcher::OpenVpnMatcher,
    },
    relay_selector::{NormalSelectedRelay, RelaySelector, SelectedRelay, SelectorConfig},
    GetRelay,
};

use super::{SelectedObfuscator, RETRY_ORDER};

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
        port_ranges: vec![
            (53, 53),
            (443, 443),
            (4000, 33433),
            (33565, 51820),
            (52000, 60000),
        ],
        ipv4_gateway: "10.64.0.1".parse().unwrap(),
        ipv6_gateway: "fc00:bbbb:bbbb:bb01::1".parse().unwrap(),
        udp2tcp_ports: vec![],
    },
});

// Some nifty constants.
const UDP: TransportProtocol = TransportProtocol::Udp;
const TCP: TransportProtocol = TransportProtocol::Tcp;

// Helper functions
fn get_relay(get_result: GetRelay) -> Relay {
    unwrap_relay_selector_result(get_result).exit_relay
}

fn unwrap_relay_selector_result(get_result: GetRelay) -> NormalSelectedRelay {
    match get_result {
        GetRelay::Wireguard {
            relay,
            entry,
            obfuscator,
        } => relay,
        GetRelay::OpenVpn { relay, bridge } => relay,
        GetRelay::Custom(custom) => {
            panic!("Can not extract regular relay from custom relay: {custom}")
        }
    }
}

fn extract_relay(relay: SelectedRelay) -> Relay {
    match relay {
        SelectedRelay::Normal(relay) => relay.exit_relay,
        SelectedRelay::Custom(custom) => {
            panic!("Can not extract regular relay from custom relay: {custom}")
        }
    }
}

fn tunnel_type(relay: &Relay) -> TunnelType {
    match relay.endpoint_data {
        RelayEndpointData::Openvpn | RelayEndpointData::Bridge => TunnelType::OpenVpn,
        RelayEndpointData::Wireguard(_) => TunnelType::Wireguard,
    }
}

/// Test whether the relay selector seems to respect the order as defined by [`RETRY_ORDER`].
#[test]
fn test_retry_order() {
    // In order to for the relay queries defined by `RETRY_ORDER` to always take precedence,
    // the user settings need to be 'neutral' on the type of relay that it wants to connect to.
    // A default `SelectorConfig` *should* have this property, but a more robust way to guarantee
    // this would be to create a neutral relay query and supply it to the relay selector at every
    // call to the `get_relay` function.
    let relay_selector = RelaySelector::from_list(SelectorConfig::default(), RELAYS.clone());
    let tunnel_protocols: Vec<Constraint<TunnelType>> = RETRY_ORDER
        .iter()
        .map(|relay| relay.tunnel_protocol)
        .collect();
    for (retry_attempt, tunnel_protocol) in tunnel_protocols.iter().enumerate() {
        // Check if the tunnel protocol on the relay returned from the relay selector aligns with
        // the tunnel protocol defined by the default retry strategy.
        match tunnel_protocol {
            Constraint::Any => continue,
            Constraint::Only(expected_tunnel_protocol) => {
                let relay = relay_selector.get_relay(retry_attempt).unwrap_or_else(|_| {
                    panic!(
                        "{}",
                        format!("Retry attempt {retry_attempt} did not yield any relay")
                    )
                });
                let tunnel_type = tunnel_type(&get_relay(relay));
                assert_eq!(tunnel_type, *expected_tunnel_protocol);
            }
        }
    }
}

/// If a Wireguard relay is only specified by it's hostname (and not tunnel type), the relay selector should
/// still return a relay of the correct tunnel type (Wireguard).
#[test]
fn test_prefer_wireguard_if_location_supports_it() {
    let relay_selector = RelaySelector::from_list(SelectorConfig::default(), RELAYS.clone());
    let query = any()
        .location(GeographicLocationConstraint::hostname(
            "se",
            "got",
            "se9-wireguard",
        ))
        .build();

    for retry_attempt in 0..RETRY_ORDER.len() {
        let relay = relay_selector
            .get_relay_by_query(query.clone())
            // .get_relay_by_query_and_blah(query.clone(), &RETRY_ORDER, retry_attempt)
            .unwrap();
        let tunnel_typ = tunnel_type(&get_relay(relay));
        assert_eq!(tunnel_typ, TunnelType::Wireguard);
    }
}

/// If an OpenVPN relay is only specified by it's hostname (and not tunnel type), the relay selector should
/// still return a relay of the correct tunnel type (OpenVPN).
#[test]
fn test_prefer_openvpn_if_location_supports_it() {
    let relay_selector = RelaySelector::from_list(SelectorConfig::default(), RELAYS.clone());
    let query = any()
        .location(GeographicLocationConstraint::hostname(
            "se",
            "got",
            "se-got-001",
        ))
        .build();

    for retry_attempt in 0..RETRY_ORDER.len() {
        let relay = relay_selector
            .get_relay_by_query(query.clone())
            // TODO(markus): To support this properly, the relay selector would have to be able
            // to query all relays matching a certain location constraint and check which tunnel
            // types that would be applicable. Doable, but we'll be concerned with this later.
            // .get_relay_by_query_and_blah(query.clone(), &RETRY_ORDER, retry_attempt)
            .unwrap();
        let tunnel_typ = tunnel_type(&get_relay(relay));
        assert_eq!(tunnel_typ, TunnelType::OpenVpn);
    }
}

/// If a Wireguard multihop constrant has the same entry and exit relay, the relay selector
/// should fail to come up with a valid configuration.
///
/// If instead the entry and exit relay are distinct, and assuming that the relays exist, the relay
/// selector should instead always return a valid configuration.
#[test]
fn test_wireguard_entry_hostname_collision() {
    let relay_selector = RelaySelector::from_list(SelectorConfig::default(), RELAYS.clone());
    // Define two distinct Wireguard relays.
    let host1 = GeographicLocationConstraint::hostname("se", "got", "se9-wireguard");
    let host2 = GeographicLocationConstraint::hostname("se", "got", "se10-wireguard");

    let invalid_multihop_query = wireguard::new()
        // Here we set `host1` to be the exit relay
        .location(host1.clone())
        .multihop()
        // .. and here we set `host1` to also be the entry relay!
        .entry(host1.clone())
        .build();

    // Assert that the same host cannot be used for entry and exit
    assert!(relay_selector
        .get_relay_by_query(invalid_multihop_query)
        .is_err());

    let valid_multihop_query = wireguard::new()
        .location(host1)
        .multihop()
        // We correct the erroneous query by setting `host2` as the entry relay
        .entry(host2)
        .build();

    // Assert that the new query succeeds when the entry and exit hosts differ
    assert!(relay_selector
        .get_relay_by_query(valid_multihop_query)
        .is_ok())
}

/// Assert that the relay selector does *not* return a multihop configuration where the exit and entry relay are
/// the same, even if the constraints would allow for it. Also verify that the relay selector is smart enough to
/// pick either the entry or exit relay first depending on which one ends up yielding a valid configuration.
///
/// TODO: Maybe this test should test `get_wireguard_multihop_endpoint`?
/// TODO: Repeat this 100 times.
#[test]
fn test_wireguard_entry() {
    let relay_selector = RelaySelector::from_list(SelectorConfig::default(), RELAYS.clone());
    let specific_hostname = "se10-wireguard";
    let specific_location = GeographicLocationConstraint::hostname("se", "got", specific_hostname);
    let general_location = GeographicLocationConstraint::city("se", "got");

    let query = wireguard::new()
        .location(general_location.clone())
        .multihop()
        .entry(specific_location.clone())
        .build();

    // The exit relay must not equal the entry relay
    // TODO(markus): This will currently fail because we do not follow this algorithm when
    // selecting entry+exit relays:
    //
    //      (exit <- get_relay, entry <- get_relay(exclude: exit)) <|> (entry <- get_relay, exit <- get_relay(exclude: entry))
    //
    // This remains to be implemented properly. Until then, this test will be flaky.
    let relay = relay_selector.get_relay_by_query(query).unwrap();
    match relay {
        GetRelay::Wireguard { relay, entry, .. } => {
            assert_ne!(relay.exit_relay.hostname, entry.unwrap().hostname);
        }
        wrong_relay => panic!(
            "Relay selector should have picked a Wireguard relay, instead chose {wrong_relay:?}"
        ),
    }

    let query = wireguard::new()
        .location(specific_location)
        .multihop()
        .entry(general_location)
        .build();

    let relay = relay_selector.get_relay_by_query(query).unwrap();
    match relay {
        GetRelay::Wireguard { relay, entry, .. } => {
            let entry = entry.unwrap();
            assert_ne!(relay.exit_relay.hostname, entry.hostname);
            assert_ne!(relay.exit_relay.ipv4_addr_in, entry.ipv4_addr_in);
            assert_eq!(relay.exit_relay.hostname, specific_hostname)
        }
        wrong_relay => panic!(
            "Relay selector should have picked a Wireguard relay, instead chose {wrong_relay:?}"
        ),
    }
}

/// Test that the relay selector:
/// * returns an OpenVPN relay given a constraint of a valid transport protocol + port combo
/// * does *not* return an OpenVPN relay given a constraint of an *invalid* transport protocol + port combo
#[test]
fn test_openvpn_constraints() {
    let relay_selector = RelaySelector::from_list(SelectorConfig::default(), RELAYS.clone());
    const ACTUAL_TCP_PORT: u16 = 443;
    const ACTUAL_UDP_PORT: u16 = 1194;
    const NON_EXISTENT_PORT: u16 = 1337;

    // Test all combinations of constraints, and whether they should
    // match some relay
    let constraint_combinations = [
        (openvpn::new().build(), true),
        (openvpn::new().transport_protocol(UDP).build(), true),
        (openvpn::new().transport_protocol(TCP).build(), true),
        (
            openvpn::new()
                .transport_protocol(UDP)
                .port(ACTUAL_UDP_PORT)
                .build(),
            true,
        ),
        (
            openvpn::new()
                .transport_protocol(UDP)
                .port(NON_EXISTENT_PORT)
                .build(),
            false,
        ),
        (
            openvpn::new()
                .transport_protocol(TCP)
                .port(ACTUAL_TCP_PORT)
                .build(),
            true,
        ),
        (
            openvpn::new()
                .transport_protocol(TCP)
                .port(NON_EXISTENT_PORT)
                .build(),
            false,
        ),
    ];

    let matches_constraints =
        |endpoint: Endpoint, constraints: &OpenVpnConstraintsFilter| match constraints.port {
            Constraint::Any => (),
            Constraint::Only(TransportPort { protocol, port }) => {
                assert_eq!(endpoint.protocol, protocol);
                match port {
                    Constraint::Any => (),
                    Constraint::Only(port) => assert_eq!(port, endpoint.address.port()),
                }
            }
        };

    for (query, should_match) in constraint_combinations.into_iter() {
        for retry_attempt in 0..100 {
            let relay: Result<_, Error> = relay_selector.get_relay_by_query(query.clone());
            if !should_match {
                relay.expect_err("Unexpected relay");
            } else {
                match relay.expect("Expected to find a relay") {
                    GetRelay::OpenVpn { relay, .. } =>  {
                        assert!(matches!(relay.endpoint, MullvadEndpoint::OpenVpn(_)));
                        matches_constraints(relay.endpoint.to_endpoint(), &query.openvpn_constraints);
                    },
                    wrong_relay => panic!("Relay selector should have picked an OpenVPN relay, instead chose {wrong_relay:?}")
                };
            }
        }
    }
}

/// Construct a query for multihop configuration and assert that the relay selector picks an accompanying entry relay.
#[test]
fn test_selecting_wireguard_location_will_consider_multihop() {
    let relay_selector = RelaySelector::from_list(SelectorConfig::default(), RELAYS.clone());

    for retry_attempt in 0..100 {
        let query = wireguard::new().multihop().build();
        let relay = relay_selector.get_relay_by_query(query.clone()).unwrap();
        match relay {
            GetRelay::Wireguard { entry, .. } => {
                assert!(entry.is_some());
            }
            wrong_relay => panic!("Relay selector should have picked a Wireguard relay, instead chose {wrong_relay:?}"),
        }
    }
}

/// Construct a query for multihop configuration, but the tunnel protocol is forcefully set to Any.
/// If a Wireguard relay is chosen, the relay selector should also pick an accompanying entry relay.
#[test]
fn test_selecting_any_relay_will_consider_multihop() {
    let relay_selector = RelaySelector::from_list(SelectorConfig::default(), RELAYS.clone());
    let mut query = wireguard::new().multihop().build();
    query.tunnel_protocol = Constraint::Any;

    for _ in 0..100 {
        let relay = relay_selector.get_relay_by_query(query.clone()).unwrap();
        match relay {
            GetRelay::Wireguard { relay, entry, .. } => {
                assert!(matches!(relay.endpoint, MullvadEndpoint::Wireguard(_)) && entry.is_some());
            }
            wrong_relay => panic!(
            "Relay selector should have picked a Wireguard relay, instead chose {wrong_relay:?}"
        ),
        }
    }
}

/// Construct a query for a Wireguard configuration where UDP2TCP obfuscation is selected and multihop is explicitly
/// turned off. Assert that the relay selector always return an obfuscator configuration.
#[test]
fn test_selecting_wireguard_endpoint_with_udp2tcp_obfuscation() {
    let relay_selector = RelaySelector::from_list(SelectorConfig::default(), RELAYS.clone());
    let mut query = wireguard::new().udp2tcp().build();
    query.wireguard_constraints.use_multihop = Constraint::Only(false);

    let relay = relay_selector.get_relay_by_query(query).unwrap();
    match relay {
        GetRelay::Wireguard {
            relay,
            entry,
            obfuscator,
        } => {
            assert!(entry.is_none());
            assert!(obfuscator.is_some_and(|obfuscator| matches!(
                obfuscator.config,
                ObfuscatorConfig::Udp2Tcp { .. }
            )))
        }
        wrong_relay => panic!(
            "Relay selector should have picked a Wireguard relay, instead chose {wrong_relay:?}"
        ),
    }
}

/// Construct a query for a Wireguard configuration where UDP2TCP obfuscation is set to "Auto" and multihop is
/// explicitly turned off. Assert that the relay selector does *not* return an obfuscator config.
///
/// # Note
/// This is a highly specific test which details how the relay selector should behave at the time of writing this test.
/// The cost (in latency primarily) of using obfuscation is deemed to be too high to enable it as an auto-configuration.
#[test]
fn test_selecting_wireguard_endpoint_with_auto_obfuscation() {
    let relay_selector = RelaySelector::from_list(SelectorConfig::default(), RELAYS.clone());
    let mut query = wireguard::new().build();
    query.wireguard_constraints.obfuscation = SelectedObfuscation::Auto;

    for _ in 0..100 {
        let relay = relay_selector.get_relay_by_query(query.clone()).unwrap();
        match relay {
            GetRelay::Wireguard {
                relay,
                entry,
                obfuscator,
            } => {
                assert!(obfuscator.is_none());
                // Seems redundant, but ok.
                assert_eq!(tunnel_type(&relay.exit_relay), TunnelType::Wireguard);
                assert!(matches!(relay.endpoint, MullvadEndpoint::Wireguard { .. }));
            }
            wrong_relay => panic!(
            "Relay selector should have picked a Wireguard relay, instead chose {wrong_relay:?}"
        ),
        }
    }
}

/// Construct a query for a Wireguard configuration with UDP2TCP obfuscation, and make sure that
/// all configurations contain a valid port.
#[test]
fn test_selected_wireguard_endpoints_use_correct_port_ranges() {
    const TCP2UDP_PORTS: [u16; 3] = [80, 443, 5001];
    let relay_selector = RelaySelector::from_list(SelectorConfig::default(), RELAYS.clone());
    // Note that we do *not* specify any port here!
    let query = wireguard::new().udp2tcp().build();

    for attempt in 0..1000 {
        let relay = relay_selector.get_relay_by_query(query.clone()).unwrap();
        match relay {
            GetRelay::Wireguard {
                relay,
                entry,
                obfuscator,
            } => {
                assert!(entry.is_none());
                let Some(obfuscator) = obfuscator else {
                    panic!("Relay selector should have picked an obfuscator")
                };
                assert!(match obfuscator.config {
                    ObfuscatorConfig::Udp2Tcp { endpoint } =>
                        TCP2UDP_PORTS.contains(&endpoint.port()),
                })
            }
            wrong_relay => panic!(
            "Relay selector should have picked a Wireguard relay, instead chose {wrong_relay:?}"
        ),
        };
    }
}

/// Verify that any query which sets an explicit [`Ownership`] is respected by the relay selector.
#[test]
fn test_ownership() {
    let relay_selector = RelaySelector::from_list(SelectorConfig::default(), RELAYS.clone());

    for _ in 0..100 {
        // Construct an arbitrary query for owned relays.
        let query = any().ownership(Ownership::MullvadOwned).build();
        let relay = relay_selector.get_relay_by_query(query).unwrap();
        // Check that the relay is owned by Mullvad.
        assert!(get_relay(relay).owned);
    }

    for _ in 0..100 {
        // Construct an arbitrary query for rented relays.
        let query = any().ownership(Ownership::Rented).build();
        let relay = relay_selector.get_relay_by_query(query).unwrap();
        // Check that the relay is rented.
        assert!(!get_relay(relay).owned);
    }
}

/// Verify that server and port selection varies between retry attempts.
#[test]
fn test_load_balancing() {
    const ATTEMPTS: usize = 100;
    let relay_selector = RelaySelector::from_list(SelectorConfig::default(), RELAYS.clone());
    let location = GeographicLocationConstraint::country("se");
    for query in [
        any().location(location.clone()).build(),
        wireguard::new().location(location.clone()).build(),
        openvpn::new().location(location).build(),
    ] {
        // Collect the range of unique relay ports and IP addresses over a large number of queries.
        let (ports, ips): (HashSet<u16>, HashSet<std::net::IpAddr>) = std::iter::repeat(query.clone())
            .take(ATTEMPTS)
            // Execute the query
            .map(|query| relay_selector.get_relay_by_query(query).unwrap())
            // Perform some plumbing ..
            .map(unwrap_relay_selector_result)
            .map(|relay| relay.endpoint.to_endpoint().address)
            // Extract the selected relay's port + IP address
            .map(|endpoint| (endpoint.port(), endpoint.ip()))
            .unzip();

        assert!(
            ports.len() > 1,
            "expected more than 1 port, got {ports:?}, for tunnel protocol {tunnel_protocol:?}",
            tunnel_protocol = query.tunnel_protocol,
        );
        assert!(
            ips.len() > 1,
            "expected more than 1 server, got {ips:?}, for tunnel protocol {tunnel_protocol:?}",
            tunnel_protocol = query.tunnel_protocol,
        );
    }
}

/// Construct a query for a relay with specific providers and verify that every chosen relay has
/// the correct associated provider.
#[test]
fn test_providers() {
    const EXPECTED_PROVIDERS: [&str; 2] = ["provider0", "provider2"];
    let providers = Providers::new(EXPECTED_PROVIDERS).unwrap();
    let relay_selector = RelaySelector::from_list(SelectorConfig::default(), RELAYS.clone());

    for _attempt in 0..100 {
        let query = any().providers(providers.clone()).build();
        let relay = relay_selector.get_relay_by_query(query).unwrap();

        match relay {
            GetRelay::Wireguard {
                relay,
                entry,
                obfuscator,
            } => {
                assert!(
                    EXPECTED_PROVIDERS.contains(&relay.exit_relay.provider.as_str()),
                    "cannot find provider {provider} in {EXPECTED_PROVIDERS:?}",
                    provider = relay.exit_relay.provider
                )
            }
            wrong_relay => panic!(
            "Relay selector should have picked a Wireguard relay, instead chose {wrong_relay:?}"
        ),
        };
    }
}

/// Verify that bridges are automatically used when bridge mode is set
/// to automatic.
#[test]
fn test_openvpn_auto_bridge() {
    let relay_selector = RelaySelector::from_list(SelectorConfig::default(), RELAYS.clone());
    let retry_order = [
        // This attempt should not use bridge
        openvpn::new().build(),
        // This attempt should use a bridge
        openvpn::new().bridge().build(),
    ];
    let should_use_bridge = |query: &RelayConstraintsFilter| {
        // TODO: This is really leaky ..
        matches!(
            query.openvpn_constraints.bridge_settings,
            Constraint::Only(BridgeSettingsFilter::Normal(_))
        )
    };

    for (retry_attempt, query) in retry_order.iter().cycle().enumerate().take(100) {
        let relay = relay_selector
            .get_relay_by_query_and_blah(&retry_order, retry_attempt)
            .unwrap();
        match relay {
            GetRelay::OpenVpn { bridge, .. } => {
                if should_use_bridge(query) {
                    assert!(bridge.is_some())
                } else {
                    assert!(bridge.is_none())
                }
            }
            wrong_relay => panic!(
                "Relay selector should have picked an OpenVPN relay, instead chose {wrong_relay:?}"
            ),
        }
    }
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
// TODO(markus): Come up with a better test.
#[test]
fn test_bridge_constraints() {
    let relay_selector = RelaySelector::from_list(SelectorConfig::default(), RELAYS.clone());
    let location = GeographicLocationConstraint::hostname("se", "got", "se-got-001");
    let relay_constraint = openvpn::new()
        .transport_protocol(TCP)
        .build();


    // -- Old test --
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
}
*/

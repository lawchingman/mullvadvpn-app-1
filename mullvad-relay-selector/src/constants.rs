//! TODO(markus): Document

use mullvad_types::constraints::Constraint;
use talpid_types::net::IpVersion;

pub(crate) const WIREGUARD_EXIT_PORT: Constraint<u16> = Constraint::Only(51820);
pub(crate) const WIREGUARD_EXIT_IP_VERSION: Constraint<IpVersion> = Constraint::Only(IpVersion::V4);

pub(crate) const UDP2TCP_PORTS: [u16; 2] = [80, 5001];

/// Minimum number of bridges to keep for selection when filtering by distance.
pub(crate) const MIN_BRIDGE_COUNT: usize = 5;

/// Max distance of bridges to consider for selection (km).
pub(crate) const MAX_BRIDGE_DISTANCE: f64 = 1500f64;

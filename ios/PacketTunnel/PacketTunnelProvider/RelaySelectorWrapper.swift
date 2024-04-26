//
//  RelaySelectorWrapper.swift
//  PacketTunnel
//
//  Created by pronebird on 08/08/2023.
//  Copyright © 2023 Mullvad VPN AB. All rights reserved.
//

import Foundation
import MullvadREST
import MullvadTypes
import PacketTunnelCore

struct RelaySelectorWrapper: RelaySelectorProtocol {
    let relayCache: RelayCacheProtocol
    let settingsReader: SettingsReaderProtocol

    func selectRelay(
        with constraints: RelayConstraints,
        connectionAttemptFailureCount: UInt
    ) throws -> SelectedRelayResult {
        let relays = try relayCache.read().relays
        switch try settingsReader.read().multihopState {
        case .on:
            let selectorResult = try RelaySelector.WireGuard.evaluate(
                by: RelayConstraints(
                    entryLocations: constraints.entryLocations ?? .any,
                    exitLocations: constraints.exitLocations,
                    port: constraints.port,
                    filter: constraints.filter
                ),
                in: relays,
                numberOfFailedAttempts: connectionAttemptFailureCount
            )

            return SelectedRelayResult(
                entryRelay: SelectedRelay(
                    endpoint: selectorResult.entryRelay!.endpoint,
                    hostname: selectorResult.entryRelay!.relay.hostname,
                    location: selectorResult.entryRelay!.location,
                    retryAttempts: connectionAttemptFailureCount
                ),
                exitRelay: SelectedRelay(
                    endpoint: selectorResult.exitRelay.endpoint,
                    hostname: selectorResult.exitRelay.relay.hostname,
                    location: selectorResult.exitRelay.location,
                    retryAttempts: connectionAttemptFailureCount
                )
            )

        case .off:
            let selectorResult = try RelaySelector.WireGuard.evaluate(
                by: RelayConstraints(
                    exitLocations: constraints.exitLocations,
                    port: constraints.port,
                    filter: constraints.filter
                ),
                in: relays,
                numberOfFailedAttempts: connectionAttemptFailureCount
            )

            return SelectedRelayResult(exitRelay: SelectedRelay(
                endpoint: selectorResult.exitRelay.endpoint,
                hostname: selectorResult.exitRelay.relay.hostname,
                location: selectorResult.exitRelay.location,
                retryAttempts: connectionAttemptFailureCount
            ))
        }
    }
}

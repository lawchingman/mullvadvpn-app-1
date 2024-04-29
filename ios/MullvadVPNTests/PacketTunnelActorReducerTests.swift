//
//  PacketTunnelActorReducerTests.swift
//  MullvadVPNTests
//
//  Created by Andrew Bulhak on 2024-04-29.
//  Copyright © 2024 Mullvad VPN AB. All rights reserved.
//

import MullvadTypes
@testable import PacketTunnelCore
import WireGuardKitTypes
import XCTest

final class PacketTunnelActorReducerTests: XCTestCase {
    // test data
    let selectedRelay = SelectedRelay(
        endpoint: MullvadEndpoint(
            ipv4Relay: IPv4Endpoint(ip: .loopback, port: 1300),
            ipv4Gateway: .loopback,
            ipv6Gateway: .loopback,
            publicKey: PrivateKey().publicKey.rawValue
        ),
        hostname: "se-got",
        location: Location(
            country: "",
            countryCode: "se",
            city: "",
            cityCode: "got",
            latitude: 0,
            longitude: 0
        ), retryAttempts: 0
    )
    func makeConnectionData(keyPolicy: State.KeyPolicy = .useCurrent) -> State.ConnectionData {
        State.ConnectionData(
            selectedRelay: selectedRelay,
            relayConstraints: RelayConstraints(),
            keyPolicy: keyPolicy,
            networkReachability: .reachable,
            connectionAttemptCount: 0,
            connectedEndpoint: selectedRelay.endpoint,
            transportLayer: .udp,
            remotePort: 12345
        )
    }

    // MARK: .start

    func testHandleStartWithoutPreselectedRelay() {
        // Given
        var state = State.initial
        // When
        let effects = PacketTunnelActor.reducer(&state, .start(StartOptions(launchSource: .app)))
        // Then
        XCTAssertEqual(effects, [
            .startDefaultPathObserver,
            .startTunnelMonitor,
            .startConnection(.random),
        ])
    }

    func testHandleStartWithPreselectedRelay() {
        // Given
        var state = State.initial
        // When
        let effects = PacketTunnelActor.reducer(
            &state,
            .start(StartOptions(launchSource: .app, selectedRelay: selectedRelay))
        )
        // Then
        XCTAssertEqual(effects, [
            .startDefaultPathObserver,
            .startTunnelMonitor,
            .startConnection(.preSelected(selectedRelay)),
        ])
    }

    // MARK: .stop

    func testHandleStopFromConnected() {
        // Given
        let connectionData = makeConnectionData()
        var state = State.connected(connectionData)
        // When
        let effects = PacketTunnelActor.reducer(&state, .stop)
        // Then
        XCTAssertEqual(state, .disconnecting(connectionData))
        XCTAssertEqual(effects, [
            .stopTunnelMonitor,
            .stopDefaultPathObserver,
            .stopTunnelAdapter,
        ])
    }

    func testHandleStopFromConnecting() {
        // Given
        let connectionData = makeConnectionData()
        var state = State.connecting(connectionData)
        // When
        let effects = PacketTunnelActor.reducer(&state, .stop)
        // Then
        XCTAssertEqual(state, .disconnecting(connectionData))
        XCTAssertEqual(effects, [
            .stopTunnelMonitor,
            .stopDefaultPathObserver,
            .stopTunnelAdapter,
        ])
    }

    func testHandleStopFromReconnecting() {
        // Given
        let connectionData = makeConnectionData()
        var state = State.reconnecting(connectionData)
        // When
        let effects = PacketTunnelActor.reducer(&state, .stop)
        // Then
        XCTAssertEqual(state, .disconnecting(connectionData))
        XCTAssertEqual(effects, [
            .stopTunnelMonitor,
            .stopDefaultPathObserver,
            .stopTunnelAdapter,
        ])
    }

    func testHandleStopFromError() {
        // Given
        let blockingData = State.BlockingData(
            reason: .accountExpired,
            keyPolicy: .useCurrent,
            networkReachability: .reachable,
            priorState: .connected
        )
        var state = State.error(blockingData)

        // When
        let effects = PacketTunnelActor.reducer(&state, .stop)

        // Then
        XCTAssertEqual(state, .disconnected)
        XCTAssertEqual(effects, [
            .stopDefaultPathObserver,
            .stopTunnelAdapter,
        ])
    }

    func testHandleStopFromUnconnectedStates() {
        // Given
        let states: [State] = [.initial, .disconnected]

        for var state in states {
            // When
            let effects = PacketTunnelActor.reducer(&state, .stop)

            // Then
            XCTAssertEqual(effects, [])
        }
    }

    // MARK: .reconnect

    func testHandleUserInitiatedReconnectFromConnectedStates() {
        // Given
        var state = State.connected(makeConnectionData())

        // When
        let effects = PacketTunnelActor.reducer(&state, .reconnect(.current, reason: .userInitiated))

        // Then
        XCTAssertEqual(effects, [
            .stopTunnelMonitor,
            .restartConnection(.current, .userInitiated),
        ])
    }

    func testHandleConnectionLossReconnectFromConnectedStates() {
        // Given
        var state = State.connected(makeConnectionData())

        // When
        let effects = PacketTunnelActor.reducer(&state, .reconnect(.random, reason: .connectionLoss))

        // Then
        XCTAssertEqual(effects, [
            .restartConnection(.random, .connectionLoss),
        ])
    }

    func testHandleReconnectFromDisconnectedIsNoOp() {
        // Given
        var state = State.disconnected

        // When
        let effects = PacketTunnelActor.reducer(&state, .reconnect(.random, reason: .connectionLoss))

        // Then
        XCTAssertEqual(effects, [])
    }

    func testHandleReconnectFromPQKeyNegotiationIsNoOp() {
        // Given
        var state = State.negotiatingPostQuantumKey(makeConnectionData(), PrivateKey())

        // When
        let effects = PacketTunnelActor.reducer(&state, .reconnect(.random, reason: .connectionLoss))

        // Then
        XCTAssertEqual(effects, [])
    }

    // MARK: .error

    func testHandleError() {
        // Given
        var state = State.connected(makeConnectionData())

        // When
        let effects = PacketTunnelActor.reducer(&state, .error(.deviceRevoked))

        // then
        XCTAssertEqual(effects, [
            .configureForErrorState(.deviceRevoked),
        ])
    }

    // MARK: .notifyKeyRotated

    func testHandleNotifyKeyRotatedWhileUsingCurrentKey() {
        // Given
        var state = State.connected(makeConnectionData(keyPolicy: .useCurrent))
        let date = Date()

        // When
        let effects = PacketTunnelActor.reducer(&state, .notifyKeyRotated(date))

        // then
        XCTAssertEqual(effects, [
            .cacheActiveKey(date),
        ])
    }

    func testHandleNotifyKeyRotatedWhileUsingPriorKey() {
        // Given
        let keyPolicy = State.KeyPolicy.usePrior(PrivateKey(), AutoCancellingTask(Task(operation: {})))
        var state = State.connected(makeConnectionData(keyPolicy: keyPolicy))
        let date = Date()

        // When
        let effects = PacketTunnelActor.reducer(&state, .notifyKeyRotated(date))

        // then
        XCTAssertEqual(effects, [])
    }

    // MARK: .switchKey

    func testHandleSwitchKeyFromUseCurrent() {
        // Given
        var state = State.connected(makeConnectionData(keyPolicy: .useCurrent))

        // When
        let effects = PacketTunnelActor.reducer(&state, .switchKey)

        // then
        XCTAssertEqual(effects, [])
    }

    func testHandleSwitchKeyFromUsePrior() {
        // Given
        let keyPolicy = State.KeyPolicy.usePrior(PrivateKey(), AutoCancellingTask(Task(operation: {})))
        var state = State.connected(makeConnectionData(keyPolicy: keyPolicy))

        // When
        let effects = PacketTunnelActor.reducer(&state, .switchKey)

        // then
        XCTAssertEqual(state.keyPolicy, State.KeyPolicy.useCurrent)
        XCTAssertEqual(effects, [
            .reconnect(.random),
        ])
    }

    // MARK: .monitorEvent

    func testHandleMonitorEvent_ConnectionEstablishedWhileConnecting() {
        // Given
        var connectionData = makeConnectionData()
        connectionData.connectionAttemptCount = 2
        var state = State.connecting(connectionData)

        // When
        let effects = PacketTunnelActor.reducer(&state, .monitorEvent(.connectionEstablished))

        // Then
        var expectedConnectionData = connectionData
        expectedConnectionData.connectionAttemptCount = 0
        XCTAssertEqual(state, .connected(expectedConnectionData))
        XCTAssertEqual(effects, [])
    }

    func testHandleMonitorEvent_ConnectionLostWhileConnected() {
        // Given
        let connectionData = makeConnectionData()
        var state = State.connected(connectionData)

        // When
        let effects = PacketTunnelActor.reducer(&state, .monitorEvent(.connectionLost))

        // Then
        XCTAssertEqual(effects, [
            .restartConnection(.random, .connectionLoss),
        ])
    }
}

//
//  MockTunnelMonitor.swift
//  PacketTunnelCoreTests
//
//  Created by pronebird on 05/09/2023.
//  Copyright © 2023 Mullvad VPN AB. All rights reserved.
//

import Foundation
import Network
import PacketTunnelCore

class MockTunnelMonitor: TunnelMonitorProtocol {
    enum Command {
        case start, stop
    }

    class Dispatcher {
        typealias BlockHandler = (TunnelMonitorEvent, DispatchTimeInterval) -> Void

        private let block: BlockHandler
        init(_ block: @escaping BlockHandler) {
            self.block = block
        }

        func send(_ event: TunnelMonitorEvent, after delay: DispatchTimeInterval = .never) {
            block(event, delay)
        }
    }

    typealias EventHandler = (TunnelMonitorEvent) -> Void
    typealias SimulationHandler = (Command, Dispatcher) -> Void

    private let stateLock = NSLock()

    var onEvent: EventHandler? {
        get {
            stateLock.withLock { _onEvent }
        }
        set {
            stateLock.withLock {
                _onEvent = newValue
            }
        }
    }

    private var _onEvent: EventHandler?
    private let simulationBlock: SimulationHandler

    init(_ simulationBlock: @escaping SimulationHandler) {
        self.simulationBlock = simulationBlock
    }

    func start(probeAddress: IPv4Address) {
        sendCommand(.start)
    }

    func stop() {
        sendCommand(.stop)
    }

    func onWake() {}

    func onSleep() {}

    private func dispatch(_ event: TunnelMonitorEvent, after delay: DispatchTimeInterval = .never) {
        if case .never = delay {
            onEvent?(event)
        } else {
            DispatchQueue.main.asyncAfter(wallDeadline: .now() + delay) { [weak self] in
                self?.onEvent?(event)
            }
        }
    }

    private func sendCommand(_ command: Command) {
        let dispatcher = Dispatcher { [weak self] event, delay in
            self?.dispatch(event, after: delay)
        }
        simulationBlock(.start, dispatcher)
    }
}

extension MockTunnelMonitor {
    /// Returns a mock of tunnel monitor that always reports that connection is established after 100ms after starting connection monitoring.
    static func nonFallible() -> MockTunnelMonitor {
        MockTunnelMonitor { command, dispatcher in
            if case .start = command {
                dispatcher.send(.connectionEstablished, after: .milliseconds(100))
            }
        }
    }
}
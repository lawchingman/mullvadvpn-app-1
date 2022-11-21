//
//  StartTunnelOperation.swift
//  MullvadVPN
//
//  Created by pronebird on 15/12/2021.
//  Copyright © 2021 Mullvad VPN AB. All rights reserved.
//

import Foundation
import MullvadLogging
import NetworkExtension
import Operations
import RelayCache
import RelaySelector
import TunnelProviderMessaging

class StartTunnelOperation: ResultOperation<Void, Error> {
    typealias EncodeErrorHandler = (Error) -> Void

    private let interactor: TunnelInteractor
    private let logger = Logger(label: "StartTunnelOperation")

    init(
        dispatchQueue: DispatchQueue,
        interactor: TunnelInteractor,
        completionHandler: @escaping CompletionHandler
    ) {
        self.interactor = interactor

        super.init(
            dispatchQueue: dispatchQueue,
            completionQueue: dispatchQueue,
            completionHandler: completionHandler
        )
    }

    override func main() {
        guard case .loggedIn = interactor.deviceState else {
            finish(completion: .failure(InvalidDeviceStateError()))
            return
        }

        switch interactor.tunnelStatus.state {
        case .disconnecting(.nothing):
            interactor.updateTunnelStatus { tunnelStatus in
                tunnelStatus = TunnelStatus()
                tunnelStatus.state = .disconnecting(.reconnect)
            }

            finish(completion: .success(()))

        case .disconnected, .pendingReconnect:
            do {
                let selectorResult = try interactor.selectRelay()

                makeTunnelProviderAndStartTunnel(selectorResult: selectorResult) { error in
                    self.finish(completion: OperationCompletion(error: error))
                }
            } catch {
                finish(completion: .failure(error))
            }

        default:
            finish(completion: .success(()))
        }
    }

    private func makeTunnelProviderAndStartTunnel(
        selectorResult: RelaySelectorResult,
        completionHandler: @escaping (Error?) -> Void
    ) {
        Self.makeTunnelProvider { result in
            self.dispatchQueue.async {
                do {
                    let tunnelProvider = try result.get()

                    self.setupDNSProvider { error in
                        if let error = error {
                            completionHandler(error)
                            return
                        }

                        do {
                            try self.startTunnel(
                                tunnelProvider: tunnelProvider,
                                selectorResult: selectorResult
                            )

                            completionHandler(nil)
                        } catch {
                            completionHandler(error)
                        }
                    }
                } catch {
                    completionHandler(error)
                }
            }
        }
    }

    private func startTunnel(
        tunnelProvider: TunnelProviderManagerType,
        selectorResult: RelaySelectorResult
    ) throws {
        var tunnelOptions = PacketTunnelOptions()

        do {
            try tunnelOptions.setSelectorResult(selectorResult)
        } catch {
            logger.error(
                error: error,
                message: "Failed to encode the selector result."
            )
        }

        interactor.setTunnel(
            Tunnel(tunnelProvider: tunnelProvider),
            shouldRefreshTunnelState: false
        )

        interactor.updateTunnelStatus { tunnelStatus in
            tunnelStatus = TunnelStatus()
            tunnelStatus.packetTunnelStatus.tunnelRelay = selectorResult.packetTunnelRelay
            tunnelStatus.state = .connecting(selectorResult.packetTunnelRelay)
        }

        try tunnelProvider.connection.startVPNTunnel(options: tunnelOptions.rawOptions())
    }

    private class func makeTunnelProvider(
        completionHandler: @escaping (Result<
            TunnelProviderManagerType,
            Error
        >) -> Void
    ) {
        TunnelProviderManagerType.loadAllFromPreferences { tunnelProviders, error in
            if let error = error {
                completionHandler(.failure(error))
                return
            }

            let tunnelProvider = tunnelProviders?.first ?? TunnelProviderManagerType()

            configureTunnelProvider(tunnelProvider)

            tunnelProvider.saveToPreferences { error in
                if let error = error {
                    completionHandler(.failure(error))
                } else {
                    // Refresh connection status after saving the tunnel preferences.
                    // Basically it's only necessary to do for new instances of
                    // `NETunnelProviderManager`, but we do that for the existing ones too
                    // for simplicity as it has no side effects.
                    tunnelProvider.loadFromPreferences { error in
                        completionHandler(error.map { .failure($0) } ?? .success(tunnelProvider))
                    }
                }
            }
        }
    }

    private class func configureTunnelProvider(_ tunnelProvider: TunnelProviderManagerType) {
        let protocolConfig = NETunnelProviderProtocol()
        protocolConfig.providerBundleIdentifier = ApplicationConfiguration
            .packetTunnelExtensionIdentifier
        protocolConfig.serverAddress = ""

        if #available(iOS 14.2, *) {
            protocolConfig.excludeLocalNetworks = true
        }

        tunnelProvider.isEnabled = true
        tunnelProvider.localizedDescription = "WireGuard"
        tunnelProvider.protocolConfiguration = protocolConfig

        let alwaysOnRule = NEOnDemandRuleConnect()
        alwaysOnRule.interfaceTypeMatch = .any
        tunnelProvider.onDemandRules = [alwaysOnRule]
        tunnelProvider.isOnDemandEnabled = true
    }

    private func setupDNSProvider(completion: @escaping (Error?) -> Void) {
        let dnsManager = NEDNSProxyManager.shared()

        dnsManager.loadFromPreferences { error in
            if let error = error {
                self.logger.error(error: error, message: "Failed to load DNS proxy configurations.")
                completion(error)
                return
            }

            let proto = NEDNSProxyProviderProtocol()
            proto.providerConfiguration = [:]
            proto.providerBundleIdentifier = "net.mullvad.MullvadVPN.DNSProxy"

            dnsManager.localizedDescription = "Mullvad DNS proxy"
            dnsManager.providerProtocol = proto
            dnsManager.isEnabled = true
            dnsManager.saveToPreferences { error in
                if let error = error {
                    self.logger.error(
                        error: error,
                        message: "Failed to load DNS proxy configurations."
                    )
                } else {
                    self.logger.debug("Saved DNS proxy settings.")
                }

                completion(error)
            }
        }
    }
}

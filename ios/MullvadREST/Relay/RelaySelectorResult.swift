//
//  RelaySelectorResult.swift
//  MullvadREST
//
//  Created by Mojgan on 2024-04-26.
//  Copyright © 2024 Mullvad VPN AB. All rights reserved.
//

import Foundation
import MullvadTypes

public struct RelaySelectorResult: Codable, Equatable {
    public var entryRelay: RelaySelectorMatch?
    public var exitRelay: RelaySelectorMatch
}

public struct RelaySelectorMatch: Codable, Equatable {
    public var endpoint: MullvadEndpoint
    public var relay: REST.ServerRelay
    public var location: Location
}

//
//  RelayConstraint.swift
//  MullvadTypes
//
//  Created by pronebird on 10/06/2019.
//  Copyright © 2019 Mullvad VPN AB. All rights reserved.
//

import Foundation

public protocol ConstraintsPropagation {
    var onNewConstraints: ((RelayConstraints) -> Void)? { get set }
}

public class RelayConstraintsUpdater: ConstraintsPropagation {
    public var onNewConstraints: ((RelayConstraints) -> Void)?

    public init(onNewConstraints: ((RelayConstraints) -> Void)? = nil) {
        self.onNewConstraints = onNewConstraints
    }
}

public struct RelayConstraints: Codable, Equatable, CustomDebugStringConvertible {
    @available(*, deprecated, renamed: "locations")
    private var location: RelayConstraint<RelayLocation> = .only(.country("se"))

    // Added in 2024.1
    // Changed from RelayLocations to UserSelectedRelays in 2024.3
    @available(*, deprecated, renamed: "exitLocations")
    public var locations: RelayConstraint<UserSelectedRelays> = .only(UserSelectedRelays(locations: [.country("se")]))

    // Added in 2023.3
    public var port: RelayConstraint<UInt16>
    public var filter: RelayConstraint<RelayFilter>

    // Added in 2024.4
    public var relayConstraintHop : RelayConstraintHop<UserSelectedRelays> = .single(UserSelectedRelays(locations: [.country("se")]))
//    public var hopLocations: RelayConstraint<UserSelectedRelays>
//    public var exitLocations: RelayConstraint<UserSelectedRelays>

    public var debugDescription: String {
        var description = "RelayConstraints {"
        description += entryLocations.flatMap { entryPeer in
            "entry location: \(entryPeer), "
        } ?? ""
        description += "exit location: \(exitLocations), port: \(port), filter: \(filter) }"
        return description
    }

    public init(
        entryLocations: RelayConstraint<UserSelectedRelays>? = nil,
        exitLocations: RelayConstraint<UserSelectedRelays> = .only(UserSelectedRelays(locations: [.country("se")])),
        port: RelayConstraint<UInt16> = .any,
        filter: RelayConstraint<RelayFilter> = .any
    ) {
        self.entryLocations = entryLocations
        self.exitLocations = exitLocations
        self.port = port
        self.filter = filter
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        // Added in 2023.3
        port = try container.decodeIfPresent(RelayConstraint<UInt16>.self, forKey: .port) ?? .any
        filter = try container.decodeIfPresent(RelayConstraint<RelayFilter>.self, forKey: .filter) ?? .any

        // Added in 2024.1
        locations = try container.decodeIfPresent(RelayConstraint<UserSelectedRelays>.self, forKey: .locations)
            ?? Self.migrateRelayLocation(decoder: decoder)
            ?? .only(UserSelectedRelays(locations: [.country("se")]))

        // Added in 2024.4
        entryLocations = try container.decodeIfPresent(
            RelayConstraint<UserSelectedRelays>.self,
            forKey: .entryLocations
        ) ?? nil
        exitLocations = try container
            .decodeIfPresent(RelayConstraint<UserSelectedRelays>.self, forKey: .exitLocations) ?? locations ??
            .only(UserSelectedRelays(locations: [.country("se")]))
    }
}

extension RelayConstraints {
    private static func migrateRelayLocation(decoder: Decoder) -> RelayConstraint<UserSelectedRelays>? {
        let container = try? decoder.container(keyedBy: CodingKeys.self)

        guard
            let relay = try? container?.decodeIfPresent(RelayConstraint<RelayLocation>.self, forKey: .location)
        else {
            return nil
        }

        return switch relay {
        case .any:
            .any
        case let .only(relay):
            .only(UserSelectedRelays(locations: [relay]))
        }
    }
}

enum RelayConstraintHop<T: Codable>  {
    case single(T)
    case multi(T)
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()

        let decoded = try? container.decode(String.self)
        if decoded == anyConstraint {
            self = .any
        } else {
            let onlyVariant = try container.decode(OnlyRepr.self)

            self = .only(onlyVariant.only)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()

        switch self {
        case let .single(value):
            try container.encode(value)
        case let .multi(value):
            try container.encode(MultiHopRelayConstraint(from: value))
        }
    }
}

public struct MultiHopRelayConstraint: Codable, CustomDebugStringConvertible {
    public var entryLocations: RelayConstraint<UserSelectedRelays>
    public var exitLocations: RelayConstraint<UserSelectedRelays>

    public init(
        entryLocations: RelayConstraint<UserSelectedRelays> = .any,
        exitLocations: RelayConstraint<UserSelectedRelays> = .only(UserSelectedRelays(locations: [.country("se")]))
    ) {
        self.entryLocations = entryLocations
        self.exitLocations = exitLocations
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        entryLocations = try container.decodeIfPresent(
            RelayConstraint<UserSelectedRelays>.self,
            forKey: .entryLocations
        ) ?? .any
        exitLocations = try container
            .decodeIfPresent(RelayConstraint<UserSelectedRelays>.self, forKey: .exitLocations) ??
            .only(UserSelectedRelays(locations: [.country("se")]))
    }

    public var debugDescription: String {
        "locations : { entry location: \(entryLocations), exit location: \(exitLocations) }"
    }
}

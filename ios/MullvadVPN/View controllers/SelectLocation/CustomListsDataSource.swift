//
//  CustomListsDataSource.swift
//  MullvadVPN
//
//  Created by Mojgan on 2024-02-08.
//  Copyright © 2024 Mullvad VPN AB. All rights reserved.
//

import Foundation
import MullvadREST
import MullvadTypes
import UIKit

class CustomListsDataSource: LocationDataSourceProtocol {
    private var locationList = [RelayLocation]()
    var nodeByLocation = [RelayLocation: SelectLocationNode]()
    var didTapEditCustomLists: (() -> Void)?

    init(didTapEditCustomLists: (() -> Void)? = nil) {
        self.didTapEditCustomLists = didTapEditCustomLists
    }

    var viewForHeader: UIView? {
        SelectLocationHeaderView(configuration: SelectLocationHeaderView.Configuration(
            name: SelectLocationSection.customLists.description,
            primaryAction: UIAction(
                handler: { [weak self] _ in
                    self?.didTapEditCustomLists?()
                }
            )
        ))
    }

    func search(by text: String) -> [RelayLocation] {
        []
    }

    func reload(
        _ response: REST.ServerRelaysResponse,
        relays: [REST.ServerRelay]
    ) -> [RelayLocation] {
        locationList
    }
}

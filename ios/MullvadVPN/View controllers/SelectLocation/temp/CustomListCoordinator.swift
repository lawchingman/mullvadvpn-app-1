//
//  CustomListCoordinator.swift
//  MullvadVPN
//
//  Created by Mojgan on 2024-02-26.
//  Copyright © 2024 Mullvad VPN AB. All rights reserved.
//

import Foundation
import MullvadSettings
import Routing
import UIKit

class CustomListCoordinator: Coordinator, Presentable, Presenting {
    let navigationController: UINavigationController

    var presentedViewController: UIViewController {
        navigationController
    }

    init(navigationController: UINavigationController) {
        self.navigationController = navigationController
    }

    func start() {
        let storyboard = UIStoryboard(name: "AddCustomList", bundle: nil)
        let controller = storyboard.instantiateInitialViewController() as! CustomListsViewController
        controller.delegate = self
        navigationController.pushViewController(controller, animated: false)
    }
}

extension CustomListCoordinator: CustomListsViewControllerDelegate {
    func presentAdd() {
        let coordinator = AddCustomListCoordinator(
            navigationController: CustomNavigationController(),
            customListInteractor: CustomListInteractor(repository: CustomListRepository())
        )
        coordinator.start()
        presentChild(coordinator, animated: true)
    }

    func presentEdit(item: CustomListViewModel) {
        let coordinator = EditCustomListCoordinator(
            navigationController: CustomNavigationController(),
            customListInteractor: CustomListInteractor(repository: CustomListRepository())
        )
        coordinator.start()
        presentChild(coordinator, animated: true)
    }
}

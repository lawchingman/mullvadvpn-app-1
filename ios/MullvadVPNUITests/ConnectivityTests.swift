//
//  ConnectivityTests.swift
//  MullvadVPNUITests
//
//  Created by Niklas Berglund on 2024-01-18.
//  Copyright © 2024 Mullvad VPN AB. All rights reserved.
//

import Foundation
import Network
import XCTest

class ConnectivityTests: LoggedOutUITestCase {
    let firewallAPIClient = FirewallAPIClient()

    override func tearDownWithError() throws {
        super.tearDown()
        firewallAPIClient.removeRules()
    }

    /// Verifies that the app still functions when API has been blocked
    func testAPIConnectionViaBridges() throws {
        firewallAPIClient.removeRules()
        let hasTimeAccountNumber = getAccountWithTime()

        addTeardownBlock {
            self.returnAccountWithTime(accountNumber: hasTimeAccountNumber)
            self.firewallAPIClient.removeRules()
        }

        try Networking.verifyCanAccessAPI() // Just to make sure there's no old firewall rule still active
        firewallAPIClient.createRule(try FirewallRule.makeBlockAPIAccessFirewallRule())
        try Networking.verifyCannotAccessAPI()

        LoginPage(app)
            .tapAccountNumberTextField()
            .enterText(hasTimeAccountNumber)
            .tapAccountNumberSubmitButton()

        // After creating firewall rule first login attempt might fail. One more attempt is allowed since the app is cycling between two methods.
        let successIconShown = LoginPage(app)
            .getSuccessIconShown()

        if successIconShown {
            HeaderBar(app)
                .verifyDeviceLabelShown()
        } else {
            LoginPage(app)
                .verifyFailIconShown()
                .tapAccountNumberSubmitButton()
                .verifySuccessIconShown()

            HeaderBar(app)
                .verifyDeviceLabelShown()
        }
    }
}

//
//  LoginPage.swift
//  MullvadVPNUITests
//
//  Created by Niklas Berglund on 2024-01-10.
//  Copyright © 2024 Mullvad VPN AB. All rights reserved.
//

import Foundation
import XCTest

class LoginPage: Page {
    @discardableResult override init(_ app: XCUIApplication) {
        super.init(app)

        self.pageAccessibilityIdentifier = .loginView
        waitForPageToBeShown()
    }

    @discardableResult public func tapAccountNumberTextField() -> Self {
        app.textFields[AccessibilityIdentifier.loginTextField].tap()
        return self
    }

    @discardableResult public func tapAccountNumberSubmitButton() -> Self {
        app.buttons[AccessibilityIdentifier.loginTextFieldButton].tap()
        return self
    }

    @discardableResult public func tapCreateAccountButton() -> Self {
        app.buttons[AccessibilityIdentifier.createAccountButton].tap()
        return self
    }

    @discardableResult public func verifySuccessIconShown() -> Self {
        let predicate = NSPredicate(format: "identifier == 'statusImageView' AND value == 'success'")
        let elementQuery = app.images.containing(predicate)
        let elementExists = elementQuery.firstMatch.waitForExistence(timeout: BaseUITestCase.defaultTimeout)
        XCTAssertTrue(elementExists)
        return self
    }

    @discardableResult public func verifyFailIconShown() -> Self {
        let predicate = NSPredicate(format: "identifier == 'statusImageView' AND value == 'fail'")
        let elementQuery = app.images.containing(predicate)
        let elementExists = elementQuery.firstMatch.waitForExistence(timeout: BaseUITestCase.defaultTimeout)
        XCTAssertTrue(elementExists)
        return self
    }

    /// Wait for success icon to be shown. Returns true if shown, false if timing out without the icon being shown
    func waitForSuccessIcon() throws -> Self {
        let statusIcon = app.images[.statusImageView]
        XCTAssertEqual(statusIcon.accessibilityValue, "success", "Showing success status icon")
        return self
    }

    /// Checks whether success icon is being shown
    func getSuccessIconShown() -> Bool {
        let predicate = NSPredicate(format: "identifier == 'statusImageView' AND value == 'success'")
        let elementQuery = app.images.containing(predicate)
        let elementExists = elementQuery.firstMatch.waitForExistence(timeout: BaseUITestCase.defaultTimeout)
        return elementExists
    }
}

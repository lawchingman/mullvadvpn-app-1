//
//  SelectLocationPage.swift
//  MullvadVPNUITests
//
//  Created by Niklas Berglund on 2024-01-11.
//  Copyright © 2024 Mullvad VPN AB. All rights reserved.
//

import Foundation
import XCTest

class SelectLocationPage: Page {
    @discardableResult override init(_ app: XCUIApplication) {
        super.init(app)

        self.pageAccessibilityIdentifier = .selectLocationView
        waitForPageToBeShown()
    }

    @discardableResult func tapLocationCell(withName name: String) -> Self {
        app.tables[AccessibilityIdentifier.selectLocationTableView].cells.staticTexts[name].tap()
        return self
    }

    @discardableResult func tapLocationCellExpandButton(withName name: String) -> Self {
        let table = app.tables[AccessibilityIdentifier.selectLocationTableView]
        let matchingCells = table.cells.containing(.any, identifier: name)
        let buttons = matchingCells.buttons
        let expandButton = buttons[AccessibilityIdentifier.expandButton]

        expandButton.tap()

        return self
    }

    @discardableResult func tapLocationCellCollapseButton(withName name: String) -> Self {
        let table = app.tables[AccessibilityIdentifier.selectLocationTableView]
        let matchingCells = table.cells.containing(.any, identifier: name)
        let buttons = matchingCells.buttons
        let collapseButton = buttons[AccessibilityIdentifier.collapseButton]

        collapseButton.tap()

        return self
    }

    @discardableResult func closeSelectLocationPage() -> Self {
        let doneButton = app.buttons[.closeSelectLocationButton]
        doneButton.tap()
        return self
    }

    @discardableResult func tapCustomListEllipsisButton() -> Self {
        let customListEllipsisButtons = app.buttons
            .matching(identifier: AccessibilityIdentifier.openCustomListsMenuButton.rawValue).allElementsBoundByIndex

        for ellipsisButton in customListEllipsisButtons where ellipsisButton.isHittable {
            ellipsisButton.tap()
            return self
        }

        XCTFail("Found no hittable custom list ellipsis button")

        return self
    }

    @discardableResult func tapAddNewCustomList() -> Self {
        let addNewCustomListButton = app.buttons[AccessibilityIdentifier.addNewCustomListButton]
        addNewCustomListButton.tap()
        return self
    }

    @discardableResult func editExistingCustomLists() -> Self {
        let editCustomListsButton = app.buttons[AccessibilityIdentifier.editCustomListButton]
        editCustomListsButton.tap()
        return self
    }

    @discardableResult func cellWithIdentifier(identifier: String) -> XCUIElement {
        app.tables[AccessibilityIdentifier.selectLocationTableView].cells[identifier]
    }

    func locationCellIsExpanded(_ name: String) -> Bool {
        let matchingCells = app.cells.containing(.any, identifier: name)
        return matchingCells.buttons[AccessibilityIdentifier.expandButton].exists ? false : true
    }

    func verifyEditCustomListsButtonIs(enabled: Bool) {
        let editCustomListsButton = app.buttons[AccessibilityIdentifier.editCustomListButton]
        XCTAssertTrue(editCustomListsButton.isEnabled == enabled)
    }
}

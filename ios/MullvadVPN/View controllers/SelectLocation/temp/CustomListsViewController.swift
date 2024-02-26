//
//  CustomListsViewController.swift
//  MullvadVPN
//
//  Created by Mojgan on 2024-02-26.
//  Copyright © 2024 Mullvad VPN AB. All rights reserved.
//

import UIKit
protocol CustomListsViewControllerDelegate: NSObjectProtocol {
    func presentAdd()
    func presentEdit(item: CustomListViewModel)
}

class CustomListsViewController: UITableViewController {
    weak var delegate: CustomListsViewControllerDelegate?
    override func viewDidLoad() {
        super.viewDidLoad()

        view.backgroundColor = .secondaryColor

        navigationController?.navigationBar.prefersLargeTitles = true

        navigationItem.title = NSLocalizedString(
            "NAVIGATION_TITLE",
            tableName: "CustomLists",
            value: "Custom lists",
            comment: ""
        )

        tableView.allowsMultipleSelection = false
        tableView.tableHeaderView = UIView()
    }

    @IBAction func add(_ sender: Any) {
        self.delegate?.presentAdd()
    }

    /*
     // MARK: - Navigation

     // In a storyboard-based application, you will often want to do a little preparation before navigation
     override func prepare(for segue: UIStoryboardSegue, sender: Any?) {
         // Get the new view controller using segue.destination.
         // Pass the selected object to the new view controller.
     }
     */

    override func tableView(_ tableView: UITableView, viewForHeaderInSection section: Int) -> UIView? {
        let label = UILabel()

        let body = NSLocalizedString(
            "ACCESS_METHOD_HEADER_BODY",
            tableName: "APIAccess",
            value: "Manage default and setup custom lists to access the relays.",
            comment: ""
        )

        let paragraphStyle = NSMutableParagraphStyle()
        paragraphStyle.lineBreakMode = .byWordWrapping

        let defaultTextAttributes: [NSAttributedString.Key: Any] = [
            .font: UIFont.systemFont(ofSize: 13),
            .foregroundColor: UIColor.ContentHeading.textColor,
        ]

        let attributedString = NSMutableAttributedString()
        attributedString.append(NSAttributedString(string: body, attributes: defaultTextAttributes))
        attributedString.append(NSAttributedString(string: " ", attributes: defaultTextAttributes))
        attributedString.addAttribute(
            .paragraphStyle,
            value: paragraphStyle,
            range: NSRange(location: 0, length: attributedString.length)
        )

        label.attributedText = attributedString

        return label
    }

    override func tableView(_ tableView: UITableView, heightForHeaderInSection section: Int) -> CGFloat {
        50.0
    }

    override func tableView(_ tableView: UITableView, viewForFooterInSection section: Int) -> UIView? {
        nil
    }

    override func tableView(_ tableView: UITableView, heightForFooterInSection section: Int) -> CGFloat {
        .greatestFiniteMagnitude
    }
    
    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        self.delegate?.presentEdit(item: CustomListViewModel(id: UUID(), name: "Netflix", locations: [.country("se")], tableSections: [.addLocations]))
    }
}

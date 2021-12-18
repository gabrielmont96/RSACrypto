//
//  RSAKeysViewController.swift
//  RSACrypto
//
//  Created by Gabriel Monteiro Camargo da Silva - GCM on 22/07/21.
//

import UIKit

class RSAKeysViewController: UIViewController {
    let rsaKeyManager: RSAKeyManagerProtocol = RSAKeyManager()

    @IBOutlet weak var privKeyTableView: UITableView!
    @IBOutlet weak var pubKeyTableView: UITableView!
    
    var publicKey: String?
    var privateKey: String?
    
    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        setup()
    }
    
    func setup() {
        navigationController?.navigationBar.isHidden = true
        
        privKeyTableView.delegate = self
        privKeyTableView.dataSource = self
        
        pubKeyTableView.delegate = self
        pubKeyTableView.dataSource = self
        
        privKeyTableView.register(UITableViewCell.self, forCellReuseIdentifier: "cell")
        pubKeyTableView.register(UITableViewCell.self, forCellReuseIdentifier: "cell")
    }

    @IBAction func generate(_ sender: Any) {
        clearFields()
        guard let pair = rsaKeyManager.generateKeyPair() else { return }
        publicKey = pair.publicKey.toString()
        privateKey = pair.privateKey.toString()
        reloadTableView()
    }
    
    @IBAction func deleteKeys(_ sender: Any) {
        guard rsaKeyManager.delete() else {
            print("delete failed")
            return
        }
        
        clearFields()
    }
    
    func clearFields() {
        publicKey = nil
        privateKey = nil
        reloadTableView()
    }
    
    func reloadTableView() {
        privKeyTableView.reloadData()
        pubKeyTableView.reloadData()
    }
}

extension RSAKeysViewController: UITableViewDataSource, UITableViewDelegate {
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        switch tableView {
        case privKeyTableView:
            return privateKey != nil ? 1 : 0
        case pubKeyTableView:
            return publicKey != nil ? 1 : 0
        default:
            return 0
        }
    }
    
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        if let cell = tableView.dequeueReusableCell(withIdentifier: "cell") {
            switch tableView {
            case privKeyTableView:
                cell.textLabel?.text = privateKey
            case pubKeyTableView:
                cell.textLabel?.text = publicKey
            default:
                break
            }
            cell.textLabel?.numberOfLines = 0
            return cell
        }
        
        return UITableViewCell()
    }
}

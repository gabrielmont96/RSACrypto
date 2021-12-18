//
//  EncryptionViewController.swift
//  RSACrypto
//
//  Created by Gabriel Monteiro Camargo da Silva - GCM on 22/07/21.
//

import UIKit

class EncryptionViewController: UIViewController {
    let rsaKeyManager: RSAKeyManagerProtocol = RSAKeyManager()
    
    @IBOutlet weak var textView: UITextView!
    @IBOutlet weak var tableView: UITableView!
    
    let alertController = UIAlertController(title: "Decrypted text", message: nil, preferredStyle: .alert)
    var encryptedData: Data?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setup()
    }
    
    func setup() {
        textView.delegate = self
        navigationController?.navigationBar.isHidden = false
        tableView.delegate = self
        tableView.dataSource = self
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "cell")
        
        let alertAction = UIAlertAction(title: "Close", style: .cancel)
        alertController.addAction(alertAction)
    }

    @IBAction func encryptionButton(_ sender: Any) {
        if let encryptedData = rsaKeyManager.encrypt(textView.text.data(using: .utf8) ?? Data()) {
            self.encryptedData = encryptedData
            tableView.reloadData()
        } else {
            alertController.title = "Attention!"
            alertController.message = "You need to generate the RSA keys first."
            presentAlert(alertController)
        }
    }
    
    @IBAction func decryptionButton(_ sender: Any) {
        alertController.title = "Decrypted text"
        guard let data = encryptedData else {
            alertController.message = "You need to encrypt first!"
            presentAlert(alertController)
            return
        }
        
        if let data = rsaKeyManager.decrypt(data), let decryptedText = String(data: data, encoding: .utf8) {
            alertController.message = decryptedText
        } else {
            alertController.message = "Failed to retrieve RSA private key."
        }
        
        presentAlert(alertController)
    }
    
    func presentAlert(_ alert: UIAlertController) {
        present(alert, animated: true)
    }
}

extension EncryptionViewController: UITextViewDelegate {
    func textViewDidChange(_ textView: UITextView) {
        encryptedData = nil
        tableView.reloadData()
    }
}

extension EncryptionViewController: UITableViewDelegate, UITableViewDataSource {
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return encryptedData != nil ? 1 : 0

    }
    
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        if let cell = tableView.dequeueReusableCell(withIdentifier: "cell") {
            cell.textLabel?.text = encryptedData?.base64EncodedString()
            cell.textLabel?.numberOfLines = 0
            return cell
        }
        
        return UITableViewCell()
    }
}

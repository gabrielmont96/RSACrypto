//
//  RSAKeyManager.swift
//  RSACrypto
//
//  Created by Gabriel Monteiro Camargo da Silva - GCM on 22/07/21.
//

import Security
import UIKit

protocol RSAKeyManagerProtocol {
    func generateKeyPair() -> RSAKeyPair?
    func delete() -> Bool
    func encrypt(_ data: Data) -> Data?
    func decrypt(_ data: Data) -> Data?
}

class RSAKeyManager: RSAKeyManagerProtocol {
    let keyPairFactory: RSAKeyPairFactoryProtocol = RSAKeyPairFactory()
    
    func generateKeyPair() -> RSAKeyPair? {
        guard let keyPair = keyPairFactory.build() else { return nil }
        
        let status = save(privateKey: keyPair.privateKey)
        guard status == errSecSuccess else {
            print("generateKeyPair() - save failed")
            log(Int(status), (SecCopyErrorMessageString(status, nil) ?? "error" as CFString) as String)
            return nil
        }
        
        print("saved with success")
        return .init(privateKey: keyPair.privateKey, publicKey: keyPair.publicKey)
    }
    
    private func save(privateKey: SecKey) -> OSStatus {
        let key = privateKey
        let addquery: [String: Any] = [kSecClass as String: kSecClassKey,
                                       kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                                       kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                                       kSecAttrApplicationTag as String: keyPairFactory.tag,
                                       kSecValueRef as String: key]
        var status = SecItemAdd(addquery as CFDictionary, nil)
        
        if status == errSecDuplicateItem {
            print("save() - duplicated key")
            log(Int(status), (SecCopyErrorMessageString(status, nil) ?? "error" as CFString) as String)
            status = SecItemDelete(addquery as CFDictionary)
            let newstatus = SecItemAdd(addquery as CFDictionary, nil)
            status = newstatus
            print("save() - new status")
            print("save() - \(newstatus == noErr)")
        }
        
        return status
    }
    
    func delete() -> Bool {
        let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                    kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                                    kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                                    kSecAttrApplicationTag as String: keyPairFactory.tag,
                                    kSecReturnRef as String: kCFBooleanTrue!]
        let status = SecItemDelete(query as CFDictionary)
        
        if status != noErr {
            print("delete() - status != noErr")
            log(Int(status), (SecCopyErrorMessageString(status, nil) ?? "error" as CFString) as String)
            return false
        }
        
        print("deleted with success")
        return true
    }
    
    private func getPublicKey() -> SecKey? {
        guard let privKey = getPrivateKey() else {
            return nil
        }
        
        guard let pubKey = SecKeyCopyPublicKey(privKey) else {
            print("getPublicKey() - status != noErr")
            return nil
        }
        
        return pubKey
    }
    
    private func getPrivateKey() -> SecKey? {
        let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                    kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                                    kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                                    kSecAttrApplicationTag as String: keyPairFactory.tag,
                                    kSecReturnRef as String: kCFBooleanTrue!]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        guard status == errSecSuccess else {
            print("getPrivateKey() - status != noErr")
            log(Int(status), (SecCopyErrorMessageString(status, nil) ?? "error" as CFString) as String)
            return nil
        }
        
        guard let key = item else {
            print("getPrivateKey() - key is nil")
            return nil
        }
        
        return (key as! SecKey)
    }
    
    func encrypt(_ data: Data) -> Data? {
        guard let privateKey = getPublicKey() else {
            print("encrypt() - publicKey could not be recovered")
            return nil
        }
        
        return encrypt(data, key: privateKey)
    }
    
    private func encrypt(_ data: Data, key: SecKey) -> Data {
        let algorithm: SecKeyAlgorithm = .rsaEncryptionPKCS1
        guard SecKeyIsAlgorithmSupported(key, .encrypt, algorithm) else {
            print("encrypt () - \(algorithm) not supported")
            return data
        }
        var error: Unmanaged<CFError>?
        
        guard let cipherText = SecKeyCreateEncryptedData(key,
                                                         algorithm,
                                                         data as CFData,
                                                         &error) as Data? else {
            print("encrypt() - \(String(describing: error?.takeRetainedValue()))")
            return data
        }
        return cipherText
    }
    
    func decrypt(_ data: Data) -> Data? {
        guard let privateKey = getPrivateKey() else {
            print("decrypt() - privateKey could not be recovered")
            return nil
        }
        
        return decrypt(data, key: privateKey)
    }
    
    private func decrypt(_ data: Data, key: SecKey) -> Data {
        let algorithm: SecKeyAlgorithm = .rsaEncryptionPKCS1
        guard SecKeyIsAlgorithmSupported(key, .decrypt, algorithm) else {
            print("decrypt() - \(algorithm) not supported")
            return data
        }
        
        var error: Unmanaged<CFError>?
        
        guard let cipherText = SecKeyCreateDecryptedData(key,
                                                         algorithm,
                                                         data as CFData,
                                                         &error) else {
            print("decrypt() - \(String(describing: error?.takeRetainedValue()))")
            return data
        }
        
        return cipherText as Data
    }
    
    func log(_ code: Int, _ message: String) {
        print("---------------------")
        print("code -> \(code)")
        print("description -> \(message)")
        print("---------------------")
    }
}

extension SecKey {
    func toString() -> String {
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCopyExternalRepresentation(self, &error) as Data? else {
            print("failed")
            return ""
        }
        
        return key.base64EncodedString()
    }
}

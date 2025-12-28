import Foundation
import Security
import React

@objc(CertificateManager)
class CertificateManager: NSObject {
    
    @objc
    static func requiresMainQueueSetup() -> Bool {
        return false
    }
    
    /// Store a private key in the iOS Keychain
    /// NOTE: If you're using react-native-ecc-csr, keys are already stored!
    /// This method is only needed if you're manually managing keys.
    /// - Parameters:
    ///   - privateKeyPEM: Private key in PEM format
    ///   - alias: Alias to identify the key in Keychain
    ///   - callback: Callback with result
    @objc
    func storePrivateKey(
        _ privateKeyPEM: String,
        alias: String,
        callback: @escaping RCTResponseSenderBlock
    ) {
        do {
            // Parse PEM to get key data
            let keyData = try parsePrivateKeyPEM(privateKeyPEM)
            
            // Determine key type (RSA or ECC)
            // ECC keys are smaller and use different attributes
            let keyType = privateKeyPEM.contains("EC PRIVATE KEY") ? 
                kSecAttrKeyTypeECSECPrimeRandom : kSecAttrKeyTypeRSA
            
            // Use ApplicationTag (same as react-native-ecc-csr)
            let tag = alias.data(using: .utf8)!
            
            // Create key attributes
            let keyAttributes: [String: Any] = [
                kSecAttrKeyType as String: keyType,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                kSecAttrKeySizeInBits as String: privateKeyPEM.contains("EC PRIVATE KEY") ? 384 : 2048
            ]
            
            var error: Unmanaged<CFError>?
            guard let privateKey = SecKeyCreateWithData(
                keyData as CFData,
                keyAttributes as CFDictionary,
                &error
            ) else {
                let errorMsg = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
                callback([NSNull(), "Failed to create private key: \(errorMsg)"])
                return
            }
            
            // Store in Keychain with ApplicationTag (matching react-native-ecc-csr)
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: tag,  // ✅ Use ApplicationTag
                kSecValueRef as String: privateKey,
                kSecAttrIsPermanent as String: true,
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked
            ]
            
            // Delete existing key with same alias if present
            SecItemDelete(query as CFDictionary)
            
            let status = SecItemAdd(query as CFDictionary, nil)
            
            if status == errSecSuccess {
                NSLog("✓ Private key stored successfully with alias: \(alias)")
                callback(["Private key stored successfully", NSNull()])
            } else {
                let errorMsg = "Failed to store private key: \(status)"
                NSLog("❌ \(errorMsg)")
                callback([NSNull(), errorMsg])
            }
            
        } catch {
            callback([NSNull(), "Error storing private key: \(error.localizedDescription)"])
        }
    }
    
    /// Store a certificate in the iOS Keychain
    /// - Parameters:
    ///   - certificatePEM: Certificate in PEM format
    ///   - alias: Alias to identify the certificate in Keychain
    ///   - callback: Callback with result
    @objc
    func storeCertificate(
        _ certificatePEM: String,
        alias: String,
        callback: @escaping RCTResponseSenderBlock
    ) {
        do {
            let certificates = try parseCertificatesFromPEM(certificatePEM)
            
            guard let certificate = certificates.first else {
                callback([NSNull(), "No certificate found in PEM"])
                return
            }
            
            let query: [String: Any] = [
                kSecClass as String: kSecClassCertificate,
                kSecAttrLabel as String: alias,
                kSecValueRef as String: certificate,
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked
            ]
            
            // Delete existing certificate with same alias if present
            SecItemDelete(query as CFDictionary)
            
            let status = SecItemAdd(query as CFDictionary, nil)
            
            if status == errSecSuccess {
                NSLog("✓ Certificate stored successfully with alias: \(alias)")
                callback(["Certificate stored successfully", NSNull()])
            } else {
                let errorMsg = "Failed to store certificate: \(status)"
                NSLog("❌ \(errorMsg)")
                callback([NSNull(), errorMsg])
            }
            
        } catch {
            callback([NSNull(), "Error storing certificate: \(error.localizedDescription)"])
        }
    }
    
    /// Delete a private key from Keychain
    @objc
    func deletePrivateKey(
        _ alias: String,
        callback: @escaping RCTResponseSenderBlock
    ) {
        let tag = alias.data(using: .utf8)!
        
        // Try to delete both ECC and RSA keys with this alias
        let eccQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom
        ]
        
        let rsaQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA
        ]
        
        let eccStatus = SecItemDelete(eccQuery as CFDictionary)
        let rsaStatus = SecItemDelete(rsaQuery as CFDictionary)
        
        if eccStatus == errSecSuccess || rsaStatus == errSecSuccess || 
           eccStatus == errSecItemNotFound || rsaStatus == errSecItemNotFound {
            NSLog("✓ Private key deleted (or didn't exist): \(alias)")
            callback(["Private key deleted successfully", NSNull()])
        } else {
            let errorMsg = "Failed to delete private key: ECC=\(eccStatus), RSA=\(rsaStatus)"
            NSLog("❌ \(errorMsg)")
            callback([NSNull(), errorMsg])
        }
    }
    
    /// Delete a certificate from Keychain
    @objc
    func deleteCertificate(
        _ alias: String,
        callback: @escaping RCTResponseSenderBlock
    ) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: alias
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        
        if status == errSecSuccess || status == errSecItemNotFound {
            NSLog("✓ Certificate deleted (or didn't exist): \(alias)")
            callback(["Certificate deleted successfully", NSNull()])
        } else {
            let errorMsg = "Failed to delete certificate: \(status)"
            NSLog("❌ \(errorMsg)")
            callback([NSNull(), errorMsg])
        }
    }
    
    /// List all keys and certificates in Keychain
    @objc
    func listKeychainItems(_ callback: @escaping RCTResponseSenderBlock) {
        var items: [[String: String]] = []
        
        // Query ECC keys (from react-native-ecc-csr)
        let eccKeyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        
        var eccResult: AnyObject?
        let eccStatus = SecItemCopyMatching(eccKeyQuery as CFDictionary, &eccResult)
        
        if eccStatus == errSecSuccess,
           let eccItems = eccResult as? [[String: Any]] {
            for item in eccItems {
                // Try ApplicationTag first (react-native-ecc-csr format)
                if let tagData = item[kSecAttrApplicationTag as String] as? Data,
                   let alias = String(data: tagData, encoding: .utf8) {
                    items.append(["type": "ecc-key", "alias": alias])
                }
                // Fallback to Label
                else if let label = item[kSecAttrLabel as String] as? String {
                    items.append(["type": "ecc-key", "alias": label])
                }
            }
        }
        
        // Query RSA keys
        let rsaKeyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        
        var rsaResult: AnyObject?
        let rsaStatus = SecItemCopyMatching(rsaKeyQuery as CFDictionary, &rsaResult)
        
        if rsaStatus == errSecSuccess,
           let rsaItems = rsaResult as? [[String: Any]] {
            for item in rsaItems {
                if let tagData = item[kSecAttrApplicationTag as String] as? Data,
                   let alias = String(data: tagData, encoding: .utf8) {
                    items.append(["type": "rsa-key", "alias": alias])
                }
                else if let label = item[kSecAttrLabel as String] as? String {
                    items.append(["type": "rsa-key", "alias": label])
                }
            }
        }
        
        // Query certificates
        let certQuery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        
        var certResult: AnyObject?
        let certStatus = SecItemCopyMatching(certQuery as CFDictionary, &certResult)
        
        if certStatus == errSecSuccess,
           let certItems = certResult as? [[String: Any]] {
            for item in certItems {
                if let label = item[kSecAttrLabel as String] as? String {
                    items.append(["type": "certificate", "alias": label])
                }
            }
        }
        
        callback([items, NSNull()])
    }
    
    // MARK: - Helper Functions
    
    private func parsePrivateKeyPEM(_ pem: String) throws -> Data {
        // Remove PEM headers and whitespace
        var cleanPem = pem
            .replacingOccurrences(of: "-----BEGIN PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "-----END PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "-----BEGIN RSA PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "-----END RSA PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
            .replacingOccurrences(of: " ", with: "")
        
        guard let data = Data(base64Encoded: cleanPem) else {
            throw NSError(domain: "CertificateManager", code: -1,
                        userInfo: [NSLocalizedDescriptionKey: "Invalid base64 encoding in private key"])
        }
        
        return data
    }
    
    private func parseCertificatesFromPEM(_ pem: String) throws -> [SecCertificate] {
        var certificates: [SecCertificate] = []
        let lines = pem.components(separatedBy: "\n")
        var currentCert = ""
        var inCert = false
        
        for line in lines {
            if line.contains("-----BEGIN CERTIFICATE-----") {
                inCert = true
                currentCert = line + "\n"
            } else if line.contains("-----END CERTIFICATE-----") {
                currentCert += line + "\n"
                inCert = false
                
                if let certData = currentCert.data(using: .utf8),
                   let cert = SecCertificateCreateWithData(nil, certData as CFData) {
                    certificates.append(cert)
                }
                currentCert = ""
            } else if inCert {
                currentCert += line + "\n"
            }
        }
        
        if certificates.isEmpty {
            throw NSError(domain: "CertificateManager", code: -1,
                        userInfo: [NSLocalizedDescriptionKey: "No certificates found in PEM"])
        }
        
        return certificates
    }
}

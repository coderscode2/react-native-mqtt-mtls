import Foundation
import CocoaMQTT
import Security
import React

@objc(MqttModule)
class MqttModule: RCTEventEmitter {
    private var mqttClient: CocoaMQTT?
    private let TAG = "MqttModule"
    
    override init() {
        super.init()
        NSLog("=== MqttModule Initialized ===")
    }
    
    override func supportedEvents() -> [String]! {
        return ["MqttConnected", "MqttDisconnected", "MqttMessage", "MqttDeliveryComplete"]
    }
    
    override static func requiresMainQueueSetup() -> Bool {
        return false
    }
    
    // MARK: - React Methods (Matching Android API Exactly)
    
    @objc
    func connect(
        _ broker: String,
        clientId: String,
        certificates: NSDictionary,
        sniHostname: String?,
        brokerIp: String?,
        successCallback: @escaping RCTResponseSenderBlock,
        errorCallback: @escaping RCTResponseSenderBlock
    ) {
        do {
            NSLog("╔════════════════════════════════════════════════════════════════")
            NSLog("║ MQTT Connection Request")
            NSLog("╠════════════════════════════════════════════════════════════════")
            NSLog("║ Broker: \(broker)")
            NSLog("║ Client ID: \(clientId)")
            NSLog("║ SNI Hostname: \(sniHostname ?? "nil")")
            NSLog("║ Broker IP: \(brokerIp ?? "nil")")
            NSLog("║ Timestamp: \(Date())")
            NSLog("╚════════════════════════════════════════════════════════════════")
            
            // Extract certificates (matching Android structure)
            let clientCertPem = certificates["clientCert"] as? String
            let privateKeyAlias = certificates["privateKeyAlias"] as? String
            let rootCaPem = certificates["rootCa"] as? String
            
            // Validate required parameters (matching Android validation)
            guard let rootCa = rootCaPem, let clientCert = clientCertPem, let keyAlias = privateKeyAlias else {
                let error = "Missing required parameters. Please provide clientCert, privateKeyAlias, and rootCa."
                NSLog("❌ \(error)")
                NSLog("  clientCert provided: \(clientCertPem != nil)")
                NSLog("  privateKeyAlias provided: \(privateKeyAlias != nil)")
                NSLog("  rootCa provided: \(rootCaPem != nil)")
                errorCallback([error])
                return
            }
            
            NSLog("✓ All required parameters provided")
            NSLog("  Client cert length: \(clientCert.count) bytes")
            NSLog("  Private key alias: \(keyAlias)")
            NSLog("  Root CA length: \(rootCa.count) bytes")
            
            // Parse broker URL
            guard let url = URL(string: broker) else {
                throw NSError(domain: "MqttModule", code: -1,
                            userInfo: [NSLocalizedDescriptionKey: "Invalid broker URL"])
            }
            
            // Use brokerIp if provided, otherwise use URL host
            let host = brokerIp ?? url.host ?? ""
            let port = UInt16(url.port ?? 8883)
            let useTLS = url.scheme == "ssl" || url.scheme == "mqtts"
            
            NSLog("")
            NSLog("┌─────────────────────────────────────────────────────────────")
            NSLog("│ Creating MQTT Client")
            NSLog("└─────────────────────────────────────────────────────────────")
            NSLog("  Host: \(host)")
            NSLog("  Port: \(port)")
            NSLog("  Use TLS: \(useTLS)")
            
            // Create MQTT client
            let client = CocoaMQTT(clientID: clientId, host: host, port: port)
            client.username = ""
            client.password = ""
            client.keepAlive = 60
            client.cleanSession = false
            client.autoReconnect = true
            
            if useTLS {
                NSLog("")
                NSLog("┌─────────────────────────────────────────────────────────────")
                NSLog("│ Creating SSL Configuration")
                NSLog("└─────────────────────────────────────────────────────────────")
                
                let sslSettings = try self.createSSLSettings(
                    privateKeyAlias: keyAlias,
                    clientCertPem: clientCert,
                    rootCaPem: rootCa,
                    sniHostname: sniHostname
                )
                
                client.enableSSL = true
                client.allowUntrustCACertificate = false
                client.sslSettings = sslSettings
                
                NSLog("✓ SSL settings configured")
            }
            
            // Setup callbacks (matching Android events)
            client.didConnectAck = { [weak self] _, ack in
                guard let self = self else { return }
                
                if ack == .accept {
                    NSLog("╔════════════════════════════════════════════════════════════════")
                    NSLog("║ ✓✓✓ MQTT SUCCESSFULLY CONNECTED ✓✓✓")
                    NSLog("╠════════════════════════════════════════════════════════════════")
                    NSLog("║ Broker: \(broker)")
                    NSLog("║ Client ID: \(clientId)")
                    NSLog("║ Timestamp: \(Date())")
                    NSLog("╚════════════════════════════════════════════════════════════════")
                    
                    self.sendEvent(withName: "MqttConnected", body: "Connected")
                    successCallback(["Connected to \(broker)"])
                } else {
                    let error = "Connection rejected: \(ack)"
                    NSLog("❌ \(error)")
                    errorCallback([error])
                }
            }
            
            client.didReceiveMessage = { [weak self] _, message, _ in
                guard let self = self else { return }
                NSLog("📨 Message received on topic: \(message.topic)")
                
                self.sendEvent(withName: "MqttMessage", body: [
                    "topic": message.topic,
                    "message": message.string ?? "",
                    "qos": message.qos.rawValue
                ])
            }
            
            client.didPublishMessage = { [weak self] _, message, _ in
                guard let self = self else { return }
                NSLog("📤 Message delivered: \(message.topic)")
                
                self.sendEvent(withName: "MqttDeliveryComplete", body: [
                    "topic": message.topic,
                    "messageId": message.msgid
                ])
            }
            
            client.didDisconnect = { [weak self] _, error in
                guard let self = self else { return }
                let errorMsg = error?.localizedDescription ?? "Unknown error"
                
                NSLog("╔════════════════════════════════════════════════════════════════")
                NSLog("║ ❌ MQTT Disconnected")
                NSLog("╠════════════════════════════════════════════════════════════════")
                NSLog("║ Error: \(errorMsg)")
                NSLog("║ Timestamp: \(Date())")
                NSLog("╚════════════════════════════════════════════════════════════════")
                
                self.sendEvent(withName: "MqttDisconnected", body: errorMsg)
            }
            
            self.mqttClient = client
            
            NSLog("")
            NSLog("╔════════════════════════════════════════════════════════════════")
            NSLog("║ Connecting to Broker...")
            NSLog("╚════════════════════════════════════════════════════════════════")
            
            _ = client.connect()
            
        } catch {
            NSLog("❌ Error: \(error.localizedDescription)")
            errorCallback([error.localizedDescription])
        }
    }
    
    @objc
    func disconnect(_ successCallback: @escaping RCTResponseSenderBlock,
                   errorCallback: @escaping RCTResponseSenderBlock) {
        guard let client = mqttClient else {
            errorCallback(["No active connection"])
            return
        }
        
        NSLog("📡 Disconnecting from broker...")
        client.disconnect()
        mqttClient = nil
        successCallback(["Disconnected"])
    }
    
    @objc
    func subscribe(_ topic: String, qos: NSInteger,
                  successCallback: @escaping RCTResponseSenderBlock,
                  errorCallback: @escaping RCTResponseSenderBlock) {
        guard let client = mqttClient else {
            errorCallback(["No active connection"])
            return
        }
        
        guard client.connState == .connected else {
            errorCallback(["Client not connected"])
            return
        }
        
        NSLog("📥 Subscribing to topic: \(topic) with QoS \(qos)")
        let mqttQos = CocoaMQTTQoS(rawValue: UInt8(qos)) ?? .qos1
        client.subscribe(topic, qos: mqttQos)
        successCallback(["Subscribed to \(topic)"])
    }
    
    @objc
    func unsubscribe(_ topic: String,
                    successCallback: @escaping RCTResponseSenderBlock,
                    errorCallback: @escaping RCTResponseSenderBlock) {
        guard let client = mqttClient else {
            errorCallback(["No active connection"])
            return
        }
        
        guard client.connState == .connected else {
            errorCallback(["Client not connected"])
            return
        }
        
        NSLog("📤 Unsubscribing from topic: \(topic)")
        client.unsubscribe(topic)
        successCallback(["Unsubscribed from \(topic)"])
    }
    
    @objc
    func publish(_ topic: String, message: String, qos: NSInteger, retained: Bool,
                successCallback: @escaping RCTResponseSenderBlock,
                errorCallback: @escaping RCTResponseSenderBlock) {
        guard let client = mqttClient else {
            errorCallback(["No active connection"])
            return
        }
        
        guard client.connState == .connected else {
            errorCallback(["Client not connected"])
            return
        }
        
        NSLog("📤 Publishing to topic: \(topic)")
        let mqttQos = CocoaMQTTQoS(rawValue: UInt8(qos)) ?? .qos1
        client.publish(topic, withString: message, qos: mqttQos, retained: retained)
        successCallback(["Published to \(topic)"])
    }
    
    @objc
    func isConnected(_ callback: @escaping RCTResponseSenderBlock) {
        let connected = mqttClient?.connState == .connected
        callback([connected])
    }
    
    // MARK: - SSL Configuration (SecIdentity for mTLS)
    
    private func createSSLSettings(
        privateKeyAlias: String,
        clientCertPem: String,
        rootCaPem: String,
        sniHostname: String?
    ) throws -> [String: NSObject] {
        
        var settings: [String: NSObject] = [:]
        
        // Parse root CA
        let caCerts = try parseCertificatesFromPEM(rootCaPem)
        guard !caCerts.isEmpty else {
            throw NSError(domain: "MqttModule", code: -1,
                        userInfo: [NSLocalizedDescriptionKey: "No CA certificates found"])
        }
        
        settings["kCFStreamSSLTrustedCertificates"] = caCerts as NSArray
        NSLog("  ✓ Root CA certificates added: \(caCerts.count)")
        
        // Create SecIdentity for client certificate
        let identity = try createIdentity(
            privateKeyAlias: privateKeyAlias,
            clientCertPem: clientCertPem
        )
        
        settings["kCFStreamSSLCertificates"] = [identity] as NSArray
        settings["kCFStreamSSLValidatesCertificateChain"] = kCFBooleanTrue
        NSLog("  ✓ Client identity added")
        
        // SNI hostname
        if let sniHost = sniHostname {
            settings["kCFStreamSSLPeerName"] = sniHost as NSString
            NSLog("  ✓ SNI hostname configured: \(sniHost)")
        }
        
        NSLog("✓ SSL configuration complete")
        return settings
    }
    
    private func createIdentity(privateKeyAlias: String, clientCertPem: String) throws -> SecIdentity {
        // Load private key from Keychain using alias
        guard let privateKey = try loadPrivateKeyFromKeychain(alias: privateKeyAlias) else {
            throw NSError(domain: "MqttModule", code: -1,
                        userInfo: [NSLocalizedDescriptionKey: "Private key not found in Keychain: \(privateKeyAlias)"])
        }
        
        // Parse certificate from PEM
        let certificates = try parseCertificatesFromPEM(clientCertPem)
        guard let certificate = certificates.first else {
            throw NSError(domain: "MqttModule", code: -1,
                        userInfo: [NSLocalizedDescriptionKey: "Failed to parse client certificate"])
        }
        
        // Add certificate to Keychain and create identity
        let certLabel = "MQTT_CLIENT_CERT_\(privateKeyAlias)"
        
        // Delete existing
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: certLabel
        ]
        SecItemDelete(deleteQuery as CFDictionary)
        
        // Add certificate
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecValueRef as String: certificate,
            kSecAttrLabel as String: certLabel
        ]
        
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        guard addStatus == errSecSuccess || addStatus == errSecDuplicateItem else {
            throw NSError(domain: "MqttModule", code: Int(addStatus),
                        userInfo: [NSLocalizedDescriptionKey: "Failed to add certificate to Keychain: \(addStatus)"])
        }
        
        // Query for identity
        let identityQuery: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecAttrLabel as String: certLabel,
            kSecReturnRef as String: true
        ]
        
        var identityRef: CFTypeRef?
        let identityStatus = SecItemCopyMatching(identityQuery as CFDictionary, &identityRef)
        
        guard identityStatus == errSecSuccess, let identity = identityRef as? SecIdentity else {
            throw NSError(domain: "MqttModule", code: -1,
                        userInfo: [NSLocalizedDescriptionKey: "Failed to create SecIdentity"])
        }
        
        return identity
    }
    
    private func loadPrivateKeyFromKeychain(alias: String) throws -> SecKey? {
        guard let tag = alias.data(using: .utf8) else {
            throw NSError(domain: "MqttModule", code: -1,
                        userInfo: [NSLocalizedDescriptionKey: "Invalid alias"])
        }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: tag,
            kSecReturnRef as String: true
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        guard status == errSecSuccess else {
            return nil
        }
        
        return (item as! SecKey)
    }
    
    private func parseCertificatesFromPEM(_ pem: String) throws -> [SecCertificate] {
        var certificates: [SecCertificate] = []
        
        let components = pem.components(separatedBy: "-----BEGIN CERTIFICATE-----")
        
        for component in components {
            guard component.contains("-----END CERTIFICATE-----") else {
                continue
            }
            
            guard let endRange = component.range(of: "-----END CERTIFICATE-----") else {
                continue
            }
            
            let base64 = String(component[..<endRange.lowerBound])
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .replacingOccurrences(of: "\n", with: "")
                .replacingOccurrences(of: "\r", with: "")
            
            guard let certData = Data(base64Encoded: base64),
                  let cert = SecCertificateCreateWithData(nil, certData as CFData) else {
                continue
            }
            
            certificates.append(cert)
        }
        
        return certificates
    }
}

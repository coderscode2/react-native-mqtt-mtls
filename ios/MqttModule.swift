import Foundation
import CocoaMQTT

@objc(MqttModule)
class MqttModule: RCTEventEmitter {
    
    // Configuration constants - MODIFY THESE FOR YOUR ENVIRONMENT
    private static let SNI_HOSTNAME = "APCBPGN2202-AF250300028.local"
    private static let BROKER_IP = "10.0.2.2"
    private static let BROKER_PORT: UInt16 = 8883
    
    private var mqtt: CocoaMQTT?
    
    override init() {
        super.init()
        print("=== MqttModule Initialized ===")
    }
    
    override static func requiresMainQueueSetup() -> Bool {
        return false
    }
    
    override func supportedEvents() -> [String]! {
        return ["MqttConnected", "MqttDisconnected", "MqttMessage", "MqttDeliveryComplete"]
    }
    
    // MARK: - React Native Methods
    
    @objc func connect(_ broker: String,
                      clientId: String,
                      certificates: NSDictionary,
                      successCallback: @escaping RCTResponseSenderBlock,
                      errorCallback: @escaping RCTResponseSenderBlock) {
        
        DispatchQueue.main.async {
            do {
                print("╔════════════════════════════════════════════════════════════════")
                print("║ MQTT Connection Request")
                print("╠════════════════════════════════════════════════════════════════")
                print("║ Broker: \(broker)")
                print("║ Client ID: \(clientId)")
                print("║ Timestamp: \(Date())")
                print("╚════════════════════════════════════════════════════════════════")
                
                // Extract certificate contents
                guard let clientCertPem = self.sanitizePEM(certificates["clientCert"] as? String, type: "Client Cert"),
                      let privateKeyPem = self.sanitizePEM(certificates["privateKey"] as? String, type: "Private Key"),
                      let rootCaPem = self.sanitizePEM(certificates["rootCa"] as? String, type: "Root CA") else {
                    let error = "Missing certificate content. Please provide clientCert, privateKey, and rootCa."
                    print("❌ \(error)")
                    errorCallback([error])
                    return
                }
                
                print("✓ All certificates provided and sanitized")
                print("  Client cert length: \(clientCertPem.count) bytes")
                print("  Private key length: \(privateKeyPem.count) bytes")
                print("  Root CA length: \(rootCaPem.count) bytes")
                
                // Parse certificates and create SSL settings
                print("")
                print("┌─────────────────────────────────────────────────────────────")
                print("│ Creating SSL Configuration")
                print("└─────────────────────────────────────────────────────────────")
                
                guard let sslSettings = try? self.createSSLSettings(
                    privateKeyPem: privateKeyPem,
                    clientCertPem: clientCertPem,
                    rootCaPem: rootCaPem
                ) else {
                    errorCallback(["Failed to create SSL configuration"])
                    return
                }
                
                // Create MQTT client
                print("")
                print("┌─────────────────────────────────────────────────────────────")
                print("│ Step 1: Creating MQTT Client")
                print("└─────────────────────────────────────────────────────────────")
                
                let clientID = clientId
                self.mqtt = CocoaMQTT(clientID: clientID, host: Self.BROKER_IP, port: Self.BROKER_PORT)
                
                guard let mqtt = self.mqtt else {
                    errorCallback(["Failed to create MQTT client"])
                    return
                }
                
                print("✓ MQTT client created successfully")
                
                // Configure MQTT settings
                print("")
                print("┌─────────────────────────────────────────────────────────────")
                print("│ Step 2: Configuring MQTT Options")
                print("└─────────────────────────────────────────────────────────────")
                
                mqtt.delegate = self
                mqtt.keepAlive = 60
                mqtt.cleanSession = false
                mqtt.autoReconnect = true
                mqtt.allowUntrustCACertificate = false
                mqtt.enableSSL = true
                
                print("  ✓ Keep alive: 60 seconds")
                print("  ✓ Clean session: false")
                print("  ✓ Auto reconnect: true")
                print("  ✓ SSL enabled: true")
                
                // Configure SSL with certificates
                print("")
                print("┌─────────────────────────────────────────────────────────────")
                print("│ Step 3: Configuring SSL/TLS")
                print("└─────────────────────────────────────────────────────────────")
                
                mqtt.sslSettings = [
                    kCFStreamSSLCertificates as String: sslSettings as NSObject,
                    kCFStreamSSLPeerName as String: Self.SNI_HOSTNAME as NSObject,
                    kCFStreamSSLLevel as String: "kCFStreamSocketSecurityLevelTLSv1_2" as NSObject,
                    kCFStreamSSLValidatesCertificateChain as String: NSNumber(value: true)
                ]
                
                print("  ✓ SSL configured with mTLS")
                print("  ✓ SNI hostname: \(Self.SNI_HOSTNAME)")
                print("  ✓ Connecting to IP: \(Self.BROKER_IP)")
                print("  ✓ TLS version: 1.2+")
                
                // Connect
                print("")
                print("╔════════════════════════════════════════════════════════════════")
                print("║ Step 4: Connecting to MQTT Broker")
                print("║ This may take a few seconds...")
                print("║ Broker: \(broker)")
                print("║ Client ID: \(clientId)")
                print("╚════════════════════════════════════════════════════════════════")
                
                let connectResult = mqtt.connect()
                
                if connectResult {
                    print("✓ Connection initiated successfully")
                    successCallback(["Connecting to \(broker)"])
                } else {
                    print("❌ Failed to initiate connection")
                    errorCallback(["Failed to initiate connection"])
                }
                
            } catch {
                print("")
                print("╔════════════════════════════════════════════════════════════════")
                print("║ ❌❌❌ MQTT CONNECTION FAILED")
                print("╠════════════════════════════════════════════════════════════════")
                print("║ Error: \(error.localizedDescription)")
                print("║ Timestamp: \(Date())")
                print("╚════════════════════════════════════════════════════════════════")
                
                errorCallback(["Connection failed: \(error.localizedDescription)"])
            }
        }
    }
    
    @objc func subscribe(_ topic: String,
                        qos: Int,
                        successCallback: @escaping RCTResponseSenderBlock,
                        errorCallback: @escaping RCTResponseSenderBlock) {
        
        DispatchQueue.main.async {
            print("📥 Subscribing to topic: \(topic) with QoS \(qos)")
            
            guard let mqtt = self.mqtt, mqtt.connState == .connected else {
                errorCallback(["Client not connected"])
                return
            }
            
            let mqttQos = CocoaMQTTQoS(rawValue: UInt8(qos)) ?? .qos0
            mqtt.subscribe(topic, qos: mqttQos)
            
            print("✓ Successfully subscribed to: \(topic)")
            successCallback(["Subscribed to \(topic)"])
        }
    }
    
    @objc func unsubscribe(_ topic: String,
                          successCallback: @escaping RCTResponseSenderBlock,
                          errorCallback: @escaping RCTResponseSenderBlock) {
        
        DispatchQueue.main.async {
            print("📤 Unsubscribing from topic: \(topic)")
            
            guard let mqtt = self.mqtt, mqtt.connState == .connected else {
                errorCallback(["Client not connected"])
                return
            }
            
            mqtt.unsubscribe(topic)
            
            print("✓ Successfully unsubscribed from: \(topic)")
            successCallback(["Unsubscribed from \(topic)"])
        }
    }
    
    @objc func publish(_ topic: String,
                      message: String,
                      qos: Int,
                      retained: Bool,
                      successCallback: @escaping RCTResponseSenderBlock,
                      errorCallback: @escaping RCTResponseSenderBlock) {
        
        DispatchQueue.main.async {
            print("📤 Publishing to topic: \(topic)")
            print("  Payload length: \(message.count) bytes")
            print("  QoS: \(qos)")
            print("  Retained: \(retained)")
            
            guard let mqtt = self.mqtt, mqtt.connState == .connected else {
                errorCallback(["Client not connected"])
                return
            }
            
            let mqttQos = CocoaMQTTQoS(rawValue: UInt8(qos)) ?? .qos0
            let mqttMessage = CocoaMQTTMessage(topic: topic, string: message, qos: mqttQos, retained: retained)
            
            mqtt.publish(mqttMessage)
            
            print("✓ Message published successfully")
            successCallback(["Published to \(topic)"])
        }
    }
    
    @objc func disconnect(_ successCallback: @escaping RCTResponseSenderBlock,
                         errorCallback: @escaping RCTResponseSenderBlock) {
        
        DispatchQueue.main.async {
            print("🔌 Disconnecting from MQTT broker...")
            
            guard let mqtt = self.mqtt else {
                print("⚠️ No client to disconnect")
                successCallback(["No active connection"])
                return
            }
            
            if mqtt.connState == .connected {
                mqtt.disconnect()
                print("✓ Disconnected from broker")
            }
            
            self.mqtt = nil
            print("✓ MQTT client closed")
            successCallback(["Disconnected successfully"])
        }
    }
    
    @objc func isConnected(_ callback: @escaping RCTResponseSenderBlock) {
        DispatchQueue.main.async {
            let connected = self.mqtt?.connState == .connected
            print("Connection status: \(connected ? "Connected" : "Disconnected")")
            callback([connected])
        }
    }
    
    // MARK: - Helper Methods
    
    private func sanitizePEM(_ pem: String?, type: String) -> String? {
        guard let pem = pem else { return nil }
        
        print("=== Sanitizing \(type) ===")
        print("Original length: \(pem.count)")
        
        var sanitized = pem
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
        
        // Fix PEM headers/footers
        sanitized = sanitized
            .replacingOccurrences(of: #"-{4,6}BEGIN"#, with: "-----BEGIN", options: .regularExpression)
            .replacingOccurrences(of: #"BEGIN([^-]*)-{4,6}"#, with: "BEGIN$1-----", options: .regularExpression)
            .replacingOccurrences(of: #"-{4,6}END"#, with: "-----END", options: .regularExpression)
            .replacingOccurrences(of: #"END([^-]*)-{4,6}"#, with: "END$1-----", options: .regularExpression)
        
        sanitized = sanitized.trimmingCharacters(in: .whitespacesAndNewlines)
        
        // Ensure proper spacing
        sanitized = sanitized
            .replacingOccurrences(of: #"(-----BEGIN [^-]+-----)"#, with: "$1\n", options: .regularExpression)
            .replacingOccurrences(of: #"(-----END [^-]+-----)"#, with: "\n$1", options: .regularExpression)
            .replacingOccurrences(of: #"\n\n+"#, with: "\n", options: .regularExpression)
        
        if !sanitized.hasSuffix("\n") {
            sanitized += "\n"
        }
        
        print("Sanitized length: \(sanitized.count)")
        print("\(type) sanitization complete")
        
        return sanitized
    }
    
    private func createSSLSettings(privateKeyPem: String, clientCertPem: String, rootCaPem: String) throws -> [Any] {
        print("")
        print("┌─────────────────────────────────────────────────────────────")
        print("│ Creating SSL Settings from PEM Strings")
        print("└─────────────────────────────────────────────────────────────")
        
        // Parse client certificate
        guard let clientCertData = clientCertPem.data(using: .utf8),
              let clientCert = SecCertificateCreateWithData(nil, clientCertData as CFData) else {
            print("❌ Failed to parse client certificate")
            throw NSError(domain: "MqttModule", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to parse client certificate"])
        }
        
        print("✓ Client certificate parsed successfully")
        
        // Parse private key
        guard let privateKey = try? parsePrivateKey(from: privateKeyPem) else {
            print("❌ Failed to parse private key")
            throw NSError(domain: "MqttModule", code: -2, userInfo: [NSLocalizedDescriptionKey: "Failed to parse private key"])
        }
        
        print("✓ Private key parsed successfully")
        
        // Create identity
        guard let identity = try? createIdentity(certificate: clientCert, privateKey: privateKey) else {
            print("❌ Failed to create identity")
            throw NSError(domain: "MqttModule", code: -3, userInfo: [NSLocalizedDescriptionKey: "Failed to create identity"])
        }
        
        print("✓✓✓ Client identity created successfully")
        
        // Parse root CA
        guard let rootCaData = rootCaPem.data(using: .utf8),
              let rootCaCert = SecCertificateCreateWithData(nil, rootCaData as CFData) else {
            print("❌ Failed to parse root CA certificate")
            throw NSError(domain: "MqttModule", code: -4, userInfo: [NSLocalizedDescriptionKey: "Failed to parse root CA certificate"])
        }
        
        print("✓ Root CA certificate parsed successfully")
        print("✓✓✓ SSL Settings Created Successfully")
        
        return [identity, rootCaCert]
    }
    
    private func parsePrivateKey(from pem: String) throws -> SecKey {
        var base64String = pem
            .replacingOccurrences(of: "-----BEGIN PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "-----END PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "-----BEGIN RSA PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "-----END RSA PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "-----BEGIN EC PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "-----END EC PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        
        guard let keyData = Data(base64Encoded: base64String) else {
            throw NSError(domain: "MqttModule", code: -5, userInfo: [NSLocalizedDescriptionKey: "Failed to decode Base64 private key"])
        }
        
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrIsPermanent as String: false
        ]
        
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, &error) else {
            throw NSError(domain: "MqttModule", code: -6, userInfo: [NSLocalizedDescriptionKey: "Failed to create private key"])
        }
        
        print("  Private key algorithm: RSA")
        print("  Private key class: Private")
        
        return privateKey
    }
    
    private func createIdentity(certificate: SecCertificate, privateKey: SecKey) throws -> SecIdentity {
        // Store certificate temporarily
        let certQuery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecValueRef as String: certificate,
            kSecAttrLabel as String: "TempMQTTCert"
        ]
        
        SecItemDelete(certQuery as CFDictionary)
        let certStatus = SecItemAdd(certQuery as CFDictionary, nil)
        
        if certStatus != errSecSuccess {
            print("❌ Failed to add certificate to keychain: \(certStatus)")
        }
        
        // Store private key temporarily
        let keyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecValueRef as String: privateKey,
            kSecAttrLabel as String: "TempMQTTKey"
        ]
        
        SecItemDelete(keyQuery as CFDictionary)
        let keyStatus = SecItemAdd(keyQuery as CFDictionary, nil)
        
        if keyStatus != errSecSuccess {
            print("❌ Failed to add private key to keychain: \(keyStatus)")
        }
        
        // Retrieve identity
        let identityQuery: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecReturnRef as String: true,
            kSecAttrLabel as String: "TempMQTTCert"
        ]
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(identityQuery as CFDictionary, &result)
        
        guard status == errSecSuccess, let identity = result else {
            print("❌ Failed to create identity: \(status)")
            SecItemDelete(certQuery as CFDictionary)
            SecItemDelete(keyQuery as CFDictionary)
            throw NSError(domain: "MqttModule", code: -7, userInfo: [NSLocalizedDescriptionKey: "Failed to create identity"])
        }
        
        return (identity as! SecIdentity)
    }
}

// MARK: - CocoaMQTTDelegate

extension MqttModule: CocoaMQTTDelegate {
    
    func mqtt(_ mqtt: CocoaMQTT, didConnectAck ack: CocoaMQTTConnAck) {
        print("╔════════════════════════════════════════════════════════════════")
        print("║ ✓✓✓ MQTT Connection Complete")
        print("╠════════════════════════════════════════════════════════════════")
        print("║ ACK: \(ack.rawValue)")
        print("║ Server URI: ssl://\(Self.BROKER_IP):\(Self.BROKER_PORT)")
        print("║ Timestamp: \(Date())")
        print("╚════════════════════════════════════════════════════════════════")
        
        if ack == .accept {
            sendEvent(withName: "MqttConnected", body: "Connected to broker: ssl://\(Self.BROKER_IP):\(Self.BROKER_PORT)")
        }
    }
    
    func mqtt(_ mqtt: CocoaMQTT, didStateChangeTo state: CocoaMQTTConnState) {
        print("MQTT state changed to: \(state.rawValue)")
    }
    
    func mqtt(_ mqtt: CocoaMQTT, didPublishMessage message: CocoaMQTTMessage, id: UInt16) {
        print("✓ Message delivery complete")
        print("  Topic: \(message.topic)")
        print("  Message ID: \(id)")
        
        sendEvent(withName: "MqttDeliveryComplete", body: "Message delivered")
    }
    
    func mqtt(_ mqtt: CocoaMQTT, didPublishAck id: UInt16) {
        print("✓ Publish acknowledged: \(id)")
    }
    
    func mqtt(_ mqtt: CocoaMQTT, didReceiveMessage message: CocoaMQTTMessage, id: UInt16) {
        let payload = message.string ?? ""
        print("📨 Message received on topic: \(message.topic)")
        print("  Payload length: \(payload.count) bytes")
        print("  QoS: \(message.qos.rawValue)")
        print("  Retained: \(message.retained)")
        
        let eventData: [String: Any] = [
            "topic": message.topic,
            "message": payload,
            "qos": message.qos.rawValue
        ]
        
        if let jsonData = try? JSONSerialization.data(withJSONObject: eventData),
           let jsonString = String(data: jsonData, encoding: .utf8) {
            sendEvent(withName: "MqttMessage", body: jsonString)
        }
    }
    
    func mqtt(_ mqtt: CocoaMQTT, didSubscribeTopics success: NSDictionary, failed: [String]) {
        print("✓ Successfully subscribed to topics: \(success)")
    }
    
    func mqtt(_ mqtt: CocoaMQTT, didUnsubscribeTopics topics: [String]) {
        print("✓ Successfully unsubscribed from topics: \(topics)")
    }
    
    func mqttDidPing(_ mqtt: CocoaMQTT) {
        print("MQTT ping sent")
    }
    
    func mqttDidReceivePong(_ mqtt: CocoaMQTT) {
        print("MQTT pong received")
    }
    
    func mqttDidDisconnect(_ mqtt: CocoaMQTT, withError err: Error?) {
        print("╔════════════════════════════════════════════════════════════════")
        print("║ ❌ MQTT Connection Lost")
        print("╠════════════════════════════════════════════════════════════════")
        print("║ Reason: \(err?.localizedDescription ?? "Unknown")")
        print("║ Timestamp: \(Date())")
        print("╚════════════════════════════════════════════════════════════════")
        
        sendEvent(withName: "MqttDisconnected", body: "Connection lost: \(err?.localizedDescription ?? "Unknown")")
    }
}

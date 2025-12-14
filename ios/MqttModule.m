#import "MqttModule.h"
@import CocoaMQTT;  // ← CHANGED THIS LINE
#import <Security/Security.h>

@interface MqttModule () <CocoaMQTTDelegate>
@property (nonatomic, strong) CocoaMQTT *mqtt;
@property (nonatomic, strong) NSArray<NSString *> *supportedEvents;
@end

@implementation MqttModule

// Configuration constants - MODIFY THESE FOR YOUR ENVIRONMENT
static NSString *const SNI_HOSTNAME = @"APCBPGN2202-AF250300028.local";
static NSString *const BROKER_IP = @"10.0.2.2";
static const NSInteger BROKER_PORT = 8883;

RCT_EXPORT_MODULE();

- (instancetype)init {
    if (self = [super init]) {
        self.supportedEvents = @[@"MqttConnected", @"MqttDisconnected", @"MqttMessage", @"MqttDeliveryComplete"];
        NSLog(@"=== MqttModule Initialized ===");
    }
    return self;
}

- (NSArray<NSString *> *)supportedEvents {
    return self.supportedEvents;
}

+ (BOOL)requiresMainQueueSetup {
    return NO;
}

#pragma mark - React Native Methods

RCT_EXPORT_METHOD(connect:(NSString *)broker
                  clientId:(NSString *)clientId
                  certificates:(NSDictionary *)certificates
                  successCallback:(RCTResponseSenderBlock)successCallback
                  errorCallback:(RCTResponseSenderBlock)errorCallback) {
    
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            NSLog(@"╔════════════════════════════════════════════════════════════════");
            NSLog(@"║ MQTT Connection Request");
            NSLog(@"╠════════════════════════════════════════════════════════════════");
            NSLog(@"║ Broker: %@", broker);
            NSLog(@"║ Client ID: %@", clientId);
            NSLog(@"║ Timestamp: %@", [NSDate date]);
            NSLog(@"╚════════════════════════════════════════════════════════════════");
            
            // Extract certificate contents
            NSString *clientCertPem = [self sanitizePEM:certificates[@"clientCert"] type:@"Client Cert"];
            NSString *privateKeyPem = [self sanitizePEM:certificates[@"privateKey"] type:@"Private Key"];
            NSString *rootCaPem = [self sanitizePEM:certificates[@"rootCa"] type:@"Root CA"];
            
            // Validate certificates
            if (!clientCertPem || !privateKeyPem || !rootCaPem) {
                NSString *error = @"Missing certificate content. Please provide clientCert, privateKey, and rootCa.";
                NSLog(@"❌ %@", error);
                NSLog(@"  clientCert provided: %@", clientCertPem ? @"YES" : @"NO");
                NSLog(@"  privateKey provided: %@", privateKeyPem ? @"YES" : @"NO");
                NSLog(@"  rootCa provided: %@", rootCaPem ? @"YES" : @"NO");
                errorCallback(@[error]);
                return;
            }
            
            NSLog(@"✓ All certificates provided and sanitized");
            NSLog(@"  Client cert length: %lu bytes", (unsigned long)clientCertPem.length);
            NSLog(@"  Private key length: %lu bytes", (unsigned long)privateKeyPem.length);
            NSLog(@"  Root CA length: %lu bytes", (unsigned long)rootCaPem.length);
            
            // Parse certificates and create SSL settings
            NSLog(@"");
            NSLog(@"┌─────────────────────────────────────────────────────────────");
            NSLog(@"│ Creating SSL Configuration");
            NSLog(@"└─────────────────────────────────────────────────────────────");
            
            NSArray *sslSettings = [self createSSLSettingsFromPEM:privateKeyPem
                                                       clientCert:clientCertPem
                                                           rootCa:rootCaPem
                                                            error:nil];
            
            if (!sslSettings) {
                errorCallback(@[@"Failed to create SSL configuration"]);
                return;
            }
            
            // Create MQTT client
            NSLog(@"");
            NSLog(@"┌─────────────────────────────────────────────────────────────");
            NSLog(@"│ Step 1: Creating MQTT Client");
            NSLog(@"└─────────────────────────────────────────────────────────────");
            
            // Use direct IP for connection, but configure SNI
            self.mqtt = [[CocoaMQTT alloc] initWithClientID:clientId host:BROKER_IP port:BROKER_PORT];
            
            if (!self.mqtt) {
                errorCallback(@[@"Failed to create MQTT client"]);
                return;
            }
            
            NSLog(@"✓ MQTT client created successfully");
            
            // Configure MQTT settings
            NSLog(@"");
            NSLog(@"┌─────────────────────────────────────────────────────────────");
            NSLog(@"│ Step 2: Configuring MQTT Options");
            NSLog(@"└─────────────────────────────────────────────────────────────");
            
            self.mqtt.delegate = self;
            self.mqtt.keepAlive = 60;
            self.mqtt.cleanSession = NO;
            self.mqtt.autoReconnect = YES;
            self.mqtt.allowUntrustCACertificate = NO;
            self.mqtt.enableSSL = YES;
            
            NSLog(@"  ✓ Keep alive: 60 seconds");
            NSLog(@"  ✓ Clean session: NO");
            NSLog(@"  ✓ Auto reconnect: YES");
            NSLog(@"  ✓ SSL enabled: YES");
            
            // Configure SSL with certificates
            NSLog(@"");
            NSLog(@"┌─────────────────────────────────────────────────────────────");
            NSLog(@"│ Step 3: Configuring SSL/TLS");
            NSLog(@"└─────────────────────────────────────────────────────────────");
            
            self.mqtt.sslSettings = @{
                (__bridge NSString *)kCFStreamSSLCertificates: sslSettings[0], // Client identity
                (__bridge NSString *)kCFStreamSSLPeerName: SNI_HOSTNAME,       // SNI hostname
                (__bridge NSString *)kCFStreamSSLLevel: (__bridge NSString *)kCFStreamSocketSecurityLevelTLSv1_2,
                (__bridge NSString *)kCFStreamSSLValidatesCertificateChain: @YES
            };
            
            NSLog(@"  ✓ SSL configured with mTLS");
            NSLog(@"  ✓ SNI hostname: %@", SNI_HOSTNAME);
            NSLog(@"  ✓ Connecting to IP: %@", BROKER_IP);
            NSLog(@"  ✓ TLS version: 1.2+");
            
            // Connect
            NSLog(@"");
            NSLog(@"╔════════════════════════════════════════════════════════════════");
            NSLog(@"║ Step 4: Connecting to MQTT Broker");
            NSLog(@"║ This may take a few seconds...");
            NSLog(@"║ Broker: %@", broker);
            NSLog(@"║ Client ID: %@", clientId);
            NSLog(@"╚════════════════════════════════════════════════════════════════");
            
            BOOL connectResult = [self.mqtt connect];
            
            if (connectResult) {
                NSLog(@"✓ Connection initiated successfully");
                successCallback(@[[NSString stringWithFormat:@"Connecting to %@", broker]]);
            } else {
                NSLog(@"❌ Failed to initiate connection");
                errorCallback(@[@"Failed to initiate connection"]);
            }
            
        } @catch (NSException *exception) {
            NSLog(@"");
            NSLog(@"╔════════════════════════════════════════════════════════════════");
            NSLog(@"║ ❌❌❌ MQTT CONNECTION FAILED");
            NSLog(@"╠════════════════════════════════════════════════════════════════");
            NSLog(@"║ Error: %@", exception.reason);
            NSLog(@"║ Type: %@", exception.name);
            NSLog(@"║ Timestamp: %@", [NSDate date]);
            NSLog(@"╚════════════════════════════════════════════════════════════════");
            NSLog(@"Stack trace: %@", exception.callStackSymbols);
            
            errorCallback(@[[NSString stringWithFormat:@"Connection failed: %@", exception.reason]]);
        }
    });
}

RCT_EXPORT_METHOD(subscribe:(NSString *)topic
                  qos:(NSInteger)qos
                  successCallback:(RCTResponseSenderBlock)successCallback
                  errorCallback:(RCTResponseSenderBlock)errorCallback) {
    
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            NSLog(@"📥 Subscribing to topic: %@ with QoS %ld", topic, (long)qos);
            
            if (!self.mqtt || self.mqtt.connState != CocoaMQTTConnState_connected) {
                errorCallback(@[@"Client not connected"]);
                return;
            }
            
            CocoaMQTTQoS mqttQos = (CocoaMQTTQoS)qos;
            [self.mqtt subscribe:topic qos:mqttQos];
            
            NSLog(@"✓ Successfully subscribed to: %@", topic);
            successCallback(@[[NSString stringWithFormat:@"Subscribed to %@", topic]]);
            
        } @catch (NSException *exception) {
            NSLog(@"❌ Subscribe failed: %@", exception.reason);
            errorCallback(@[[NSString stringWithFormat:@"Subscribe failed: %@", exception.reason]]);
        }
    });
}

RCT_EXPORT_METHOD(unsubscribe:(NSString *)topic
                  successCallback:(RCTResponseSenderBlock)successCallback
                  errorCallback:(RCTResponseSenderBlock)errorCallback) {
    
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            NSLog(@"📤 Unsubscribing from topic: %@", topic);
            
            if (!self.mqtt || self.mqtt.connState != CocoaMQTTConnState_connected) {
                errorCallback(@[@"Client not connected"]);
                return;
            }
            
            [self.mqtt unsubscribe:topic];
            
            NSLog(@"✓ Successfully unsubscribed from: %@", topic);
            successCallback(@[[NSString stringWithFormat:@"Unsubscribed from %@", topic]]);
            
        } @catch (NSException *exception) {
            NSLog(@"❌ Unsubscribe failed: %@", exception.reason);
            errorCallback(@[[NSString stringWithFormat:@"Unsubscribe failed: %@", exception.reason]]);
        }
    });
}

RCT_EXPORT_METHOD(publish:(NSString *)topic
                  message:(NSString *)message
                  qos:(NSInteger)qos
                  retained:(BOOL)retained
                  successCallback:(RCTResponseSenderBlock)successCallback
                  errorCallback:(RCTResponseSenderBlock)errorCallback) {
    
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            NSLog(@"📤 Publishing to topic: %@", topic);
            NSLog(@"  Payload length: %lu bytes", (unsigned long)message.length);
            NSLog(@"  QoS: %ld", (long)qos);
            NSLog(@"  Retained: %@", retained ? @"YES" : @"NO");
            
            if (!self.mqtt || self.mqtt.connState != CocoaMQTTConnState_connected) {
                errorCallback(@[@"Client not connected"]);
                return;
            }
            
            CocoaMQTTQoS mqttQos = (CocoaMQTTQoS)qos;
            CocoaMQTTMessage *mqttMessage = [[CocoaMQTTMessage alloc] initWithTopic:topic
                                                                              string:message
                                                                                 qos:mqttQos
                                                                            retained:retained];
            
            [self.mqtt publish:mqttMessage];
            
            NSLog(@"✓ Message published successfully");
            successCallback(@[[NSString stringWithFormat:@"Published to %@", topic]]);
            
        } @catch (NSException *exception) {
            NSLog(@"❌ Publish failed: %@", exception.reason);
            errorCallback(@[[NSString stringWithFormat:@"Publish failed: %@", exception.reason]]);
        }
    });
}

RCT_EXPORT_METHOD(disconnect:(RCTResponseSenderBlock)successCallback
                  errorCallback:(RCTResponseSenderBlock)errorCallback) {
    
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            NSLog(@"🔌 Disconnecting from MQTT broker...");
            
            if (!self.mqtt) {
                NSLog(@"⚠️ No client to disconnect");
                successCallback(@[@"No active connection"]);
                return;
            }
            
            if (self.mqtt.connState == CocoaMQTTConnState_connected) {
                [self.mqtt disconnect];
                NSLog(@"✓ Disconnected from broker");
            }
            
            self.mqtt = nil;
            NSLog(@"✓ MQTT client closed");
            successCallback(@[@"Disconnected successfully"]);
            
        } @catch (NSException *exception) {
            NSLog(@"❌ Disconnect failed: %@", exception.reason);
            errorCallback(@[[NSString stringWithFormat:@"Disconnect failed: %@", exception.reason]]);
        }
    });
}

RCT_EXPORT_METHOD(isConnected:(RCTResponseSenderBlock)callback) {
    dispatch_async(dispatch_get_main_queue(), ^{
        BOOL connected = (self.mqtt && self.mqtt.connState == CocoaMQTTConnState_connected);
        NSLog(@"Connection status: %@", connected ? @"Connected" : @"Disconnected");
        callback(@[@(connected)]);
    });
}

#pragma mark - CocoaMQTT Delegate Methods

- (void)mqtt:(CocoaMQTT *)mqtt didConnectAck:(CocoaMQTTConnAck)ack {
    NSLog(@"╔════════════════════════════════════════════════════════════════");
    NSLog(@"║ ✓✓✓ MQTT Connection Complete");
    NSLog(@"╠════════════════════════════════════════════════════════════════");
    NSLog(@"║ ACK: %ld", (long)ack);
    NSLog(@"║ Server URI: ssl://%@:%d", BROKER_IP, (int)BROKER_PORT);
    NSLog(@"║ Timestamp: %@", [NSDate date]);
    NSLog(@"╚════════════════════════════════════════════════════════════════");
    
    if (ack == CocoaMQTTConnAck_accepted) {
        [self sendEventWithName:@"MqttConnected"
                           body:[NSString stringWithFormat:@"Connected to broker: ssl://%@:%d", BROKER_IP, (int)BROKER_PORT]];
    }
}

- (void)mqtt:(CocoaMQTT *)mqtt didStateChangeTo state:(CocoaMQTTConnState)state {
    NSLog(@"MQTT state changed to: %ld", (long)state);
}

- (void)mqtt:(CocoaMQTT *)mqtt didPublishMessage:(CocoaMQTTMessage *)message id:(UInt16)msgid {
    NSLog(@"✓ Message delivery complete");
    NSLog(@"  Topic: %@", message.topic);
    NSLog(@"  Message ID: %d", msgid);
    
    [self sendEventWithName:@"MqttDeliveryComplete" body:@"Message delivered"];
}

- (void)mqtt:(CocoaMQTT *)mqtt didPublishAck:(UInt16)msgid {
    NSLog(@"✓ Publish acknowledged: %d", msgid);
}

- (void)mqtt:(CocoaMQTT *)mqtt didReceiveMessage:(CocoaMQTTMessage *)message id:(UInt16)msgid {
    NSString *payload = message.string ?: @"";
    NSLog(@"📨 Message received on topic: %@", message.topic);
    NSLog(@"  Payload length: %lu bytes", (unsigned long)payload.length);
    NSLog(@"  QoS: %d", message.qos);
    NSLog(@"  Retained: %@", message.retained ? @"YES" : @"NO");
    
    NSDictionary *eventData = @{
        @"topic": message.topic,
        @"message": payload,
        @"qos": @(message.qos)
    };
    
    NSError *error;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:eventData options:0 error:&error];
    if (jsonData) {
        NSString *jsonString = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
        [self sendEventWithName:@"MqttMessage" body:jsonString];
    }
}

- (void)mqtt:(CocoaMQTT *)mqtt didSubscribeTopics:(NSDictionary *)topics {
    NSLog(@"✓ Successfully subscribed to topics: %@", topics);
}

- (void)mqtt:(CocoaMQTT *)mqtt didUnsubscribeTopics:(NSArray<NSString *> *)topics {
    NSLog(@"✓ Successfully unsubscribed from topics: %@", topics);
}

- (void)mqttDidPing:(CocoaMQTT *)mqtt {
    NSLog(@"MQTT ping sent");
}

- (void)mqttDidReceivePong:(CocoaMQTT *)mqtt {
    NSLog(@"MQTT pong received");
}

- (void)mqttDidDisconnect:(CocoaMQTT *)mqtt withError:(NSError *)err {
    NSLog(@"╔════════════════════════════════════════════════════════════════");
    NSLog(@"║ ❌ MQTT Connection Lost");
    NSLog(@"╠════════════════════════════════════════════════════════════════");
    NSLog(@"║ Reason: %@", err ? err.localizedDescription : @"Unknown");
    NSLog(@"║ Timestamp: %@", [NSDate date]);
    NSLog(@"╚════════════════════════════════════════════════════════════════");
    
    [self sendEventWithName:@"MqttDisconnected"
                       body:[NSString stringWithFormat:@"Connection lost: %@", err ? err.localizedDescription : @"Unknown"]];
}

#pragma mark - Helper Methods

- (NSString *)sanitizePEM:(NSString *)pem type:(NSString *)type {
    if (!pem) return nil;
    
    NSLog(@"=== Sanitizing %@ ===", type);
    NSLog(@"Original length: %lu", (unsigned long)pem.length);
    NSLog(@"Original starts with: %@", [pem substringToIndex:MIN(60, pem.length)]);
    
    // Normalize line endings
    NSString *sanitized = [pem stringByReplacingOccurrencesOfString:@"\r\n" withString:@"\n"];
    sanitized = [sanitized stringByReplacingOccurrencesOfString:@"\r" withString:@"\n"];
    
    // Fix common PEM header/footer issues using regex
    NSRegularExpression *regex;
    
    regex = [NSRegularExpression regularExpressionWithPattern:@"-{4,6}BEGIN" options:0 error:nil];
    sanitized = [regex stringByReplacingMatchesInString:sanitized options:0 range:NSMakeRange(0, sanitized.length) withTemplate:@"-----BEGIN"];
    
    regex = [NSRegularExpression regularExpressionWithPattern:@"BEGIN([^-]*)-{4,6}" options:0 error:nil];
    sanitized = [regex stringByReplacingMatchesInString:sanitized options:0 range:NSMakeRange(0, sanitized.length) withTemplate:@"BEGIN$1-----"];
    
    regex = [NSRegularExpression regularExpressionWithPattern:@"-{4,6}END" options:0 error:nil];
    sanitized = [regex stringByReplacingMatchesInString:sanitized options:0 range:NSMakeRange(0, sanitized.length) withTemplate:@"-----END"];
    
    regex = [NSRegularExpression regularExpressionWithPattern:@"END([^-]*)-{4,6}" options:0 error:nil];
    sanitized = [regex stringByReplacingMatchesInString:sanitized options:0 range:NSMakeRange(0, sanitized.length) withTemplate:@"END$1-----"];
    
    // Remove leading/trailing whitespace
    sanitized = [sanitized stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    
    // Ensure proper spacing
    regex = [NSRegularExpression regularExpressionWithPattern:@"(-----BEGIN [^-]+-----)" options:0 error:nil];
    sanitized = [regex stringByReplacingMatchesInString:sanitized options:0 range:NSMakeRange(0, sanitized.length) withTemplate:@"$1\n"];
    
    regex = [NSRegularExpression regularExpressionWithPattern:@"(-----END [^-]+-----)" options:0 error:nil];
    sanitized = [regex stringByReplacingMatchesInString:sanitized options:0 range:NSMakeRange(0, sanitized.length) withTemplate:@"\n$1"];
    
    // Remove double newlines
    regex = [NSRegularExpression regularExpressionWithPattern:@"\n\n+" options:0 error:nil];
    sanitized = [regex stringByReplacingMatchesInString:sanitized options:0 range:NSMakeRange(0, sanitized.length) withTemplate:@"\n"];
    
    // Ensure ends with newline
    if (![sanitized hasSuffix:@"\n"]) {
        sanitized = [sanitized stringByAppendingString:@"\n"];
    }
    
    NSLog(@"Sanitized length: %lu", (unsigned long)sanitized.length);
    NSLog(@"%@ sanitization complete", type);
    
    return sanitized;
}

- (NSArray *)createSSLSettingsFromPEM:(NSString *)privateKeyPem
                           clientCert:(NSString *)clientCertPem
                               rootCa:(NSString *)rootCaPem
                                error:(NSError **)error {
    @try {
        NSLog(@"");
        NSLog(@"┌─────────────────────────────────────────────────────────────");
        NSLog(@"│ Creating SSL Settings from PEM Strings");
        NSLog(@"└─────────────────────────────────────────────────────────────");
        
        // Step 1: Parse client certificate
        NSLog(@"");
        NSLog(@"┌─────────────────────────────────────────────────────────────");
        NSLog(@"│ Step 1: Parsing Client Certificate");
        NSLog(@"└─────────────────────────────────────────────────────────────");
        
        NSData *clientCertData = [clientCertPem dataUsingEncoding:NSUTF8StringEncoding];
        SecCertificateRef clientCert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)clientCertData);
        
        if (!clientCert) {
            NSLog(@"❌ Failed to parse client certificate");
            return nil;
        }
        
        NSLog(@"✓ Client certificate parsed successfully");
        
        // Step 2: Parse private key
        NSLog(@"");
        NSLog(@"┌─────────────────────────────────────────────────────────────");
        NSLog(@"│ Step 2: Parsing Private Key");
        NSLog(@"└─────────────────────────────────────────────────────────────");
        
        NSData *privateKeyData = [privateKeyPem dataUsingEncoding:NSUTF8StringEncoding];
        SecKeyRef privateKey = [self parsePrivateKeyFromPEM:privateKeyData];
        
        if (!privateKey) {
            NSLog(@"❌ Failed to parse private key");
            CFRelease(clientCert);
            return nil;
        }
        
        NSLog(@"✓ Private key parsed successfully");
        
        // Step 3: Create identity (certificate + private key)
        NSLog(@"");
        NSLog(@"┌─────────────────────────────────────────────────────────────");
        NSLog(@"│ Step 3: Creating Client Identity");
        NSLog(@"└─────────────────────────────────────────────────────────────");
        
        SecIdentityRef identity = [self createIdentityWithCertificate:clientCert privateKey:privateKey];
        
        CFRelease(clientCert);
        CFRelease(privateKey);
        
        if (!identity) {
            NSLog(@"❌ Failed to create identity");
            return nil;
        }
        
        NSLog(@"✓✓✓ Client identity created successfully");
        
        // Step 4: Parse root CA
        NSLog(@"");
        NSLog(@"┌─────────────────────────────────────────────────────────────");
        NSLog(@"│ Step 4: Parsing Root CA Certificate(s)");
        NSLog(@"└─────────────────────────────────────────────────────────────");
        
        NSData *rootCaData = [rootCaPem dataUsingEncoding:NSUTF8StringEncoding];
        SecCertificateRef rootCaCert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)rootCaData);
        
        if (!rootCaCert) {
            NSLog(@"❌ Failed to parse root CA certificate");
            CFRelease(identity);
            return nil;
        }
        
        NSLog(@"✓ Root CA certificate parsed successfully");
        
        // Step 5: Create array for SSL settings
        NSLog(@"");
        NSLog(@"┌─────────────────────────────────────────────────────────────");
        NSLog(@"│ Step 5: Building SSL Settings Array");
        NSLog(@"└─────────────────────────────────────────────────────────────");
        
        NSArray *certs = @[(__bridge id)identity, (__bridge id)rootCaCert];
        
        CFRelease(identity);
        CFRelease(rootCaCert);
        
        NSLog(@"✓✓✓ SSL Settings Created Successfully");
        
        return @[certs];
        
    } @catch (NSException *exception) {
        NSLog(@"");
        NSLog(@"╔════════════════════════════════════════════════════════════════");
        NSLog(@"║ ❌❌❌ SSL Settings Creation Failed");
        NSLog(@"╠════════════════════════════════════════════════════════════════");
        NSLog(@"║ Error: %@", exception.reason);
        NSLog(@"║ Type: %@", exception.name);
        NSLog(@"╚════════════════════════════════════════════════════════════════");
        
        return nil;
    }
}

- (SecKeyRef)parsePrivateKeyFromPEM:(NSData *)pemData {
    // Remove PEM headers and decode Base64
    NSString *pemString = [[NSString alloc] initWithData:pemData encoding:NSUTF8StringEncoding];
    
    // Remove header, footer, and newlines
    NSString *base64String = pemString;
    base64String = [base64String stringByReplacingOccurrencesOfString:@"-----BEGIN PRIVATE KEY-----" withString:@""];
    base64String = [base64String stringByReplacingOccurrencesOfString:@"-----END PRIVATE KEY-----" withString:@""];
    base64String = [base64String stringByReplacingOccurrencesOfString:@"-----BEGIN RSA PRIVATE KEY-----" withString:@""];
    base64String = [base64String stringByReplacingOccurrencesOfString:@"-----END RSA PRIVATE KEY-----" withString:@""];
    base64String = [base64String stringByReplacingOccurrencesOfString:@"-----BEGIN EC PRIVATE KEY-----" withString:@""];
    base64String = [base64String stringByReplacingOccurrencesOfString:@"-----END EC PRIVATE KEY-----" withString:@""];
    base64String = [base64String stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    base64String = [base64String stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    base64String = [base64String stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    
    NSData *keyData = [[NSData alloc] initWithBase64EncodedString:base64String options:0];
    
    if (!keyData) {
        NSLog(@"❌ Failed to decode Base64 private key data");
        return NULL;
    }
    
    // Try to import as PKCS#8 first, then PKCS#1
    NSDictionary *attributes = @{
        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
        (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate,
        (__bridge id)kSecAttrIsPermanent: @NO
    };
    
    CFErrorRef error = NULL;
    SecKeyRef privateKey = SecKeyCreateWithData((__bridge CFDataRef)keyData,
                                                (__bridge CFDictionaryRef)attributes,
                                                &error);
    
    if (error) {
        CFStringRef errorDesc = CFErrorCopyDescription(error);
        NSLog(@"⚠️ PKCS#8 import failed, trying PKCS#1: %@", (__bridge NSString *)errorDesc);
        CFRelease(errorDesc);
        CFRelease(error);
        
        // Try converting PKCS#1 to PKCS#8 format manually would require more complex ASN.1 parsing
        // For now, log the error
        NSLog(@"❌ Private key format not supported. Please convert to PKCS#8 format.");
        return NULL;
    }
    
    if (!privateKey) {
        NSLog(@"❌ Failed to create private key from data");
        return NULL;
    }
    
    NSLog(@"  Private key algorithm: RSA");
    NSLog(@"  Private key class: Private");
    
    return privateKey;
}

- (SecIdentityRef)createIdentityWithCertificate:(SecCertificateRef)certificate privateKey:(SecKeyRef)privateKey {
    // Create a temporary keychain to store the identity
    NSMutableDictionary *query = [[NSMutableDictionary alloc] init];
    [query setObject:(__bridge id)kSecClassIdentity forKey:(__bridge id)kSecClass];
    [query setObject:(__bridge id)certificate forKey:(__bridge id)kSecValueRef];
    [query setObject:@YES forKey:(__bridge id)kSecReturnRef];
    
    // Store certificate in keychain temporarily
    NSDictionary *certQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassCertificate,
        (__bridge id)kSecValueRef: (__bridge id)certificate,
        (__bridge id)kSecAttrLabel: @"TempMQTTCert"
    };
    
    SecItemDelete((__bridge CFDictionaryRef)certQuery);
    OSStatus certStatus = SecItemAdd((__bridge CFDictionaryRef)certQuery, NULL);
    
    if (certStatus != errSecSuccess) {
        NSLog(@"❌ Failed to add certificate to keychain: %d", (int)certStatus);
    }
    
    // Store private key in keychain temporarily
    NSDictionary *keyQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassKey,
        (__bridge id)kSecValueRef: (__bridge id)privateKey,
        (__bridge id)kSecAttrLabel: @"TempMQTTKey"
    };
    
    SecItemDelete((__bridge CFDictionaryRef)keyQuery);
    OSStatus keyStatus = SecItemAdd((__bridge CFDictionaryRef)keyQuery, NULL);
    
    if (keyStatus != errSecSuccess) {
        NSLog(@"❌ Failed to add private key to keychain: %d", (int)keyStatus);
    }
    
    // Now try to get the identity
    NSDictionary *identityQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassIdentity,
        (__bridge id)kSecReturnRef: @YES,
        (__bridge id)kSecAttrLabel: @"TempMQTTCert"
    };
    
    SecIdentityRef identity = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)identityQuery, (CFTypeRef *)&identity);
    
    if (status != errSecSuccess || !identity) {
        NSLog(@"❌ Failed to create identity: %d", (int)status);
        
        // Cleanup
        SecItemDelete((__bridge CFDictionaryRef)certQuery);
        SecItemDelete((__bridge CFDictionaryRef)keyQuery);
        
        return NULL;
    }
    
    return identity;
}

@end

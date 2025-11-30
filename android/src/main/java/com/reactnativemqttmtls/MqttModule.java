package com.reactnativemqttmtls;

import android.content.Context;
import android.util.Log;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.modules.core.DeviceEventManagerModule;

import org.eclipse.paho.client.mqttv3.IMqttDeliveryToken;
import org.eclipse.paho.client.mqttv3.MqttCallbackExtended;
import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.MqttMessage;
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.StringReader;
import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.PrivateKey;
import java.security.Security;
import java.util.Collection;
import java.util.ArrayList;

import javax.net.ssl.SSLContext;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

public class MqttModule extends ReactContextBaseJavaModule {
    private static final String TAG = "MqttModule";
    private final ReactApplicationContext reactContext;
    private MqttClient client;

    public MqttModule(ReactApplicationContext reactContext) {
        super(reactContext);
        this.reactContext = reactContext;

        // Add BouncyCastle as security provider if not already added
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
            Log.d(TAG, "BouncyCastle provider added at position 1");
        } else {
            Log.d(TAG, "BouncyCastle provider already present");
        }

        Log.i(TAG, "=== MqttModule Initialized ===");
        Log.d(TAG, "Security providers available:");
        for (java.security.Provider provider : Security.getProviders()) {
            Log.d(TAG, "  - " + provider.getName() + " v" + provider.getVersion());
        }
    }

    @Override
    public String getName() {
        return "MqttModule";
    }

    private String sanitizePEM(String pem, String type) {
        if (pem == null)
            return null;

        Log.d(TAG, "=== Sanitizing " + type + " ===");
        Log.d(TAG, "Original length: " + pem.length());
        Log.d(TAG, "Original starts with: " + pem.substring(0, Math.min(60, pem.length())));

        // Normalize line endings
        String sanitized = pem.replaceAll("\\r\\n", "\n").replaceAll("\\r", "\n");

        // Fix common PEM header/footer issues
        // Replace incorrect dash counts (4 or 6 dashes) with correct 5 dashes
        sanitized = sanitized.replaceAll("-{4,6}BEGIN", "-----BEGIN");
        sanitized = sanitized.replaceAll("BEGIN([^-]*)-{4,6}", "BEGIN$1-----");
        sanitized = sanitized.replaceAll("-{4,6}END", "-----END");
        sanitized = sanitized.replaceAll("END([^-]*)-{4,6}", "END$1-----");

        // Remove any leading/trailing whitespace
        sanitized = sanitized.trim();

        // Ensure proper spacing around headers and footers
        sanitized = sanitized.replaceAll("(-----BEGIN [^-]+-----)", "$1\n");
        sanitized = sanitized.replaceAll("(-----END [^-]+-----)", "\n$1");

        // Remove any double newlines that might have been created
        sanitized = sanitized.replaceAll("\n\n+", "\n");

        // Ensure it ends with a newline
        if (!sanitized.endsWith("\n")) {
            sanitized += "\n";
        }

        Log.d(TAG, "Sanitized length: " + sanitized.length());
        Log.d(TAG, "Sanitized starts with: " + sanitized.substring(0, Math.min(60, sanitized.length())));

        // Count how many certificates/keys are in the PEM
        int beginCount = sanitized.split("-----BEGIN").length - 1;
        int endCount = sanitized.split("-----END").length - 1;
        Log.d(TAG, "Number of BEGIN markers: " + beginCount);
        Log.d(TAG, "Number of END markers: " + endCount);

        if (beginCount != endCount) {
            Log.w(TAG, "⚠️ WARNING: BEGIN and END marker count mismatch!");
        }

        Log.i(TAG, type + " sanitization complete");

        return sanitized;
    }

    @ReactMethod
    public void connect(String broker, String clientId, ReadableMap certificates, Callback successCallback,
            Callback errorCallback) {
        try {
            Log.d(TAG, "╔════════════════════════════════════════════════════════════════");
            Log.d(TAG, "║ MQTT Connection Request");
            Log.d(TAG, "╠════════════════════════════════════════════════════════════════");
            Log.d(TAG, "║ Broker: " + broker);
            Log.d(TAG, "║ Client ID: " + clientId);
            Log.d(TAG, "║ Timestamp: " + new java.util.Date().toString());
            Log.d(TAG, "╚════════════════════════════════════════════════════════════════");

            // Extract certificate contents from ReadableMap
            String clientCertPem = certificates.hasKey("clientCert")
                    ? sanitizePEM(certificates.getString("clientCert"), "Client Cert")
                    : null;
            String privateKeyAlias = certificates.hasKey("privateKeyAlias") 
                    ? certificates.getString("privateKeyAlias")
                    : null;
            String rootCaPem = certificates.hasKey("rootCa") ? sanitizePEM(certificates.getString("rootCa"), "Root CA")
                    : null;

            // Validate that all required certificates are provided
            if (clientCertPem == null || privateKeyAlias == null || rootCaPem == null) {
                String error = "Missing certificate content. Please provide clientCert, privateKeyAlias, and rootCa.";
                Log.e(TAG, "❌ " + error);
                Log.e(TAG, "  clientCert provided: " + (clientCertPem != null));
                Log.e(TAG, "  privateKeyAlias provided: " + (privateKeyAlias != null));
                Log.e(TAG, "  rootCa provided: " + (rootCaPem != null));
                errorCallback.invoke(error);
                return;
            }

            Log.i(TAG, "✓ All certificates provided and sanitized");
            Log.d(TAG, "  Client cert length: " + clientCertPem.length() + " bytes");
            Log.d(TAG, "  Private key alias: " + privateKeyAlias);
            Log.d(TAG, "  Root CA length: " + rootCaPem.length() + " bytes");

            // Initialize MQTT client
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 1: Creating MQTT Client");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");
            client = new MqttClient(broker, clientId, new MemoryPersistence());
            Log.i(TAG, "✓ MQTT client created successfully");

            // Configure connection options
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 2: Configuring MQTT Connection Options");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");

            MqttConnectOptions options = new MqttConnectOptions();

            // Set basic MQTT options
            options.setCleanSession(false);
            Log.d(TAG, "  ✓ Clean session: false");

            options.setAutomaticReconnect(true);
            Log.d(TAG, "  ✓ Automatic reconnect: true");

            options.setConnectionTimeout(30);
            Log.d(TAG, "  ✓ Connection timeout: 30 seconds");

            options.setKeepAliveInterval(60);
            Log.d(TAG, "  ✓ Keep alive interval: 60 seconds");

            // Create SSL context with keystore-based private key
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 3: Creating SSL Context");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");

            SSLContext sslContext = createSSLContextFromKeystore(privateKeyAlias, clientCertPem, rootCaPem);
            options.setSocketFactory(sslContext.getSocketFactory());
            Log.i(TAG, "✓ SSL socket factory configured");

            // Set up callback
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 4: Setting up MQTT Callbacks");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");

            client.setCallback(new MqttCallbackExtended() {
                @Override
                public void connectComplete(boolean reconnect, String serverURI) {
                    Log.i(TAG, "╔════════════════════════════════════════════════════════════════");
                    Log.i(TAG, "║ ✓✓✓ MQTT Connection Complete");
                    Log.i(TAG, "╠════════════════════════════════════════════════════════════════");
                    Log.i(TAG, "║ Reconnect: " + reconnect);
                    Log.i(TAG, "║ Server URI: " + serverURI);
                    Log.i(TAG, "║ Timestamp: " + new java.util.Date().toString());
                    Log.i(TAG, "╚════════════════════════════════════════════════════════════════");
                    sendEvent("MqttConnected", "Connected to broker: " + serverURI);
                }

                @Override
                public void connectionLost(Throwable cause) {
                    Log.e(TAG, "╔════════════════════════════════════════════════════════════════");
                    Log.e(TAG, "║ ❌ MQTT Connection Lost");
                    Log.e(TAG, "╠════════════════════════════════════════════════════════════════");
                    Log.e(TAG, "║ Reason: " + (cause != null ? cause.getMessage() : "Unknown"));
                    Log.e(TAG, "║ Timestamp: " + new java.util.Date().toString());
                    Log.e(TAG, "╚════════════════════════════════════════════════════════════════");

                    if (cause != null) {
                        Log.e(TAG, "=== Connection Lost Stack Trace ===");
                        cause.printStackTrace();
                    }

                    sendEvent("MqttDisconnected",
                            "Connection lost: " + (cause != null ? cause.getMessage() : "Unknown"));
                }

                @Override
                public void messageArrived(String topic, MqttMessage message) {
                    String payload = new String(message.getPayload());
                    Log.d(TAG, "📨 Message received on topic: " + topic);
                    Log.d(TAG, "  Payload length: " + payload.length() + " bytes");
                    Log.d(TAG, "  QoS: " + message.getQos());
                    Log.d(TAG, "  Retained: " + message.isRetained());
                    Log.d(TAG, "  Duplicate: " + message.isDuplicate());

                    // Send to React Native
                    String eventData = "{\"topic\":\"" + topic + "\",\"message\":\"" + payload + "\",\"qos\":"
                            + message.getQos() + "}";
                    sendEvent("MqttMessage", eventData);
                }

                @Override
                public void deliveryComplete(IMqttDeliveryToken token) {
                    try {
                        Log.d(TAG, "✓ Message delivery complete");
                        if (token.getMessage() != null) {
                            Log.d(TAG, "  Topics: " + java.util.Arrays.toString(token.getTopics()));
                            Log.d(TAG, "  Message ID: " + token.getMessageId());
                        }
                    } catch (Exception e) {
                        Log.w(TAG, "Could not log delivery details: " + e.getMessage());
                    }
                    sendEvent("MqttDeliveryComplete", "Message delivered");
                }
            });

            Log.i(TAG, "✓ MQTT callbacks configured");

            // Connect to broker
            Log.d(TAG, "");
            Log.d(TAG, "╔════════════════════════════════════════════════════════════════");
            Log.d(TAG, "║ Step 5: Connecting to MQTT Broker");
            Log.d(TAG, "║ This may take a few seconds...");
            Log.d(TAG, "╚════════════════════════════════════════════════════════════════");

            client.connect(options);

            Log.i(TAG, "");
            Log.i(TAG, "╔════════════════════════════════════════════════════════════════");
            Log.i(TAG, "║ ✓✓✓ MQTT CLIENT SUCCESSFULLY CONNECTED ✓✓✓");
            Log.i(TAG, "╠════════════════════════════════════════════════════════════════");
            Log.i(TAG, "║ Broker: " + broker);
            Log.i(TAG, "║ Client ID: " + clientId);
            Log.i(TAG, "║ Connection established at: " + new java.util.Date().toString());
            Log.i(TAG, "╚════════════════════════════════════════════════════════════════");

            successCallback.invoke("Connected to " + broker);

        } catch (Exception e) {
            Log.e(TAG, "");
            Log.e(TAG, "╔════════════════════════════════════════════════════════════════");
            Log.e(TAG, "║ ❌❌❌ MQTT CONNECTION FAILED");
            Log.e(TAG, "╠════════════════════════════════════════════════════════════════");
            Log.e(TAG, "║ Error: " + e.getMessage());
            Log.e(TAG, "║ Type: " + e.getClass().getName());
            Log.e(TAG, "║ Timestamp: " + new java.util.Date().toString());

            if (e.getCause() != null) {
                Log.e(TAG, "╠════════════════════════════════════════════════════════════════");
                Log.e(TAG, "║ Root Cause: " + e.getCause().getMessage());
            }
            Log.e(TAG, "╚════════════════════════════════════════════════════════════════");

            Log.e(TAG, "=== Full Stack Trace ===");
            e.printStackTrace();

            errorCallback.invoke("Connection failed: " + e.getMessage());
        }
    }

    @ReactMethod
    public void subscribe(String topic, int qos, Callback successCallback, Callback errorCallback) {
        try {
            Log.d(TAG, "📥 Subscribing to topic: " + topic + " with QoS " + qos);

            if (client == null || !client.isConnected()) {
                throw new MqttException(MqttException.REASON_CODE_CLIENT_NOT_CONNECTED);
            }

            client.subscribe(topic, qos);
            Log.i(TAG, "✓ Successfully subscribed to: " + topic);
            successCallback.invoke("Subscribed to " + topic);

        } catch (Exception e) {
            Log.e(TAG, "❌ Subscribe failed: " + e.getMessage());
            e.printStackTrace();
            errorCallback.invoke("Subscribe failed: " + e.getMessage());
        }
    }

    @ReactMethod
    public void unsubscribe(String topic, Callback successCallback, Callback errorCallback) {
        try {
            Log.d(TAG, "📤 Unsubscribing from topic: " + topic);

            if (client == null || !client.isConnected()) {
                throw new MqttException(MqttException.REASON_CODE_CLIENT_NOT_CONNECTED);
            }

            client.unsubscribe(topic);
            Log.i(TAG, "✓ Successfully unsubscribed from: " + topic);
            successCallback.invoke("Unsubscribed from " + topic);

        } catch (Exception e) {
            Log.e(TAG, "❌ Unsubscribe failed: " + e.getMessage());
            e.printStackTrace();
            errorCallback.invoke("Unsubscribe failed: " + e.getMessage());
        }
    }

    @ReactMethod
    public void publish(String topic, String message, int qos, boolean retained, Callback successCallback,
            Callback errorCallback) {
        try {
            Log.d(TAG, "📤 Publishing to topic: " + topic);
            Log.d(TAG, "  Payload length: " + message.length() + " bytes");
            Log.d(TAG, "  QoS: " + qos);
            Log.d(TAG, "  Retained: " + retained);

            if (client == null || !client.isConnected()) {
                throw new MqttException(MqttException.REASON_CODE_CLIENT_NOT_CONNECTED);
            }

            MqttMessage mqttMessage = new MqttMessage(message.getBytes());
            mqttMessage.setQos(qos);
            mqttMessage.setRetained(retained);

            client.publish(topic, mqttMessage);
            Log.i(TAG, "✓ Message published successfully");
            successCallback.invoke("Published to " + topic);

        } catch (Exception e) {
            Log.e(TAG, "❌ Publish failed: " + e.getMessage());
            e.printStackTrace();
            errorCallback.invoke("Publish failed: " + e.getMessage());
        }
    }

    @ReactMethod
    public void disconnect(Callback successCallback, Callback errorCallback) {
        try {
            Log.d(TAG, "🔌 Disconnecting from MQTT broker...");

            if (client == null) {
                Log.w(TAG, "⚠️ No client to disconnect");
                successCallback.invoke("No active connection");
                return;
            }

            if (client.isConnected()) {
                client.disconnect();
                Log.i(TAG, "✓ Disconnected from broker");
            }

            client.close();
            client = null;

            Log.i(TAG, "✓ MQTT client closed");
            successCallback.invoke("Disconnected successfully");

        } catch (Exception e) {
            Log.e(TAG, "❌ Disconnect failed: " + e.getMessage());
            e.printStackTrace();
            errorCallback.invoke("Disconnect failed: " + e.getMessage());
        }
    }

    @ReactMethod
    public void isConnected(Callback callback) {
        boolean connected = (client != null && client.isConnected());
        Log.d(TAG, "Connection status: " + (connected ? "Connected" : "Disconnected"));
        callback.invoke(connected);
    }

    /**
     * Creates an SSLContext using a private key from Android Keystore
     * 
     * @param privateKeyAlias The alias of the private key in Android Keystore
     *                        (e.g., "ECC_CSR_PRIVATE_KEY")
     * @param clientCertPem   The client certificate in PEM format
     * @param rootCaPem       The root CA certificate(s) in PEM format
     * @return Configured SSLContext
     */
    private SSLContext createSSLContextFromKeystore(String privateKeyAlias, String clientCertPem, String rootCaPem)
            throws Exception {
        try {
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Creating SSLContext from Android Keystore");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");

            // Step 1: Load Android Keystore and retrieve private key
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 1: Loading Private Key from Android Keystore");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");

            KeyStore androidKeyStore = KeyStore.getInstance("AndroidKeyStore");
            androidKeyStore.load(null);
            Log.d(TAG, "  ✓ AndroidKeyStore loaded");

            // List all aliases for debugging
            java.util.Enumeration<String> aliases = androidKeyStore.aliases();
            Log.d(TAG, "  Available aliases in AndroidKeyStore:");
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Log.d(TAG, "    - " + alias);
            }

            Log.d(TAG, "  Looking for private key with alias: " + privateKeyAlias);

            // Check if the key exists
            if (!androidKeyStore.containsAlias(privateKeyAlias)) {
                throw new Exception("Private key not found in AndroidKeyStore with alias: " + privateKeyAlias);
            }

            Log.d(TAG, "  ✓ Private key alias found in keystore");

            // Get the key entry from Android Keystore
            KeyStore.Entry entry = androidKeyStore.getEntry(privateKeyAlias, null);
            if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
                throw new Exception("Key entry is not a PrivateKeyEntry. Found: " + entry.getClass().getName());
            }

            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
            PrivateKey privateKey = privateKeyEntry.getPrivateKey();

            Log.i(TAG, "  ✓✓✓ Private key retrieved from AndroidKeyStore successfully");
            Log.d(TAG, "  Private key algorithm: " + privateKey.getAlgorithm());
            Log.d(TAG, "  Private key format: " + privateKey.getFormat());

            // Step 2: Parse client certificate
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 2: Parsing Client Certificate");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

            InputStream clientCertStream = new ByteArrayInputStream(clientCertPem.getBytes());
            Collection<? extends java.security.cert.Certificate> clientCerts = certFactory
                    .generateCertificates(clientCertStream);

            if (clientCerts.isEmpty()) {
                throw new Exception("No client certificate found in PEM");
            }

            X509Certificate clientCert = (X509Certificate) clientCerts.iterator().next();
            Log.i(TAG, "  ✓ Client certificate parsed");
            Log.d(TAG, "  Subject: " + clientCert.getSubjectDN());
            Log.d(TAG, "  Issuer: " + clientCert.getIssuerDN());
            Log.d(TAG, "  Valid from: " + clientCert.getNotBefore());
            Log.d(TAG, "  Valid until: " + clientCert.getNotAfter());
            Log.d(TAG, "  Serial: " + clientCert.getSerialNumber());

            // Step 3: Parse CA certificates
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 3: Parsing CA Certificate(s)");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");

            InputStream caStream = new ByteArrayInputStream(rootCaPem.getBytes());
            Collection<? extends java.security.cert.Certificate> caCerts = certFactory.generateCertificates(caStream);

            if (caCerts.isEmpty()) {
                throw new Exception("No CA certificates found in PEM");
            }

            Log.i(TAG, "  ✓ " + caCerts.size() + " CA certificate(s) parsed");

            int certIndex = 0;
            ArrayList<X509Certificate> caCertsList = new ArrayList<>();
            for (java.security.cert.Certificate cert : caCerts) {
                X509Certificate caCert = (X509Certificate) cert;
                caCertsList.add(caCert);
                Log.d(TAG, "  CA #" + certIndex + ":");
                Log.d(TAG, "    Subject: " + caCert.getSubjectDN());
                Log.d(TAG, "    Issuer: " + caCert.getIssuerDN());
                Log.d(TAG, "    Valid from: " + caCert.getNotBefore());
                Log.d(TAG, "    Valid until: " + caCert.getNotAfter());
                certIndex++;
            }

            // Step 4: Build certificate chain
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 4: Building Certificate Chain");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");

            ArrayList<java.security.cert.Certificate> certChainList = new ArrayList<>();
            certChainList.add(clientCert);

            // Find intermediate CA(s) by matching issuer
            String clientIssuer = clientCert.getIssuerDN().toString();
            for (X509Certificate caCert : caCertsList) {
                String caSubject = caCert.getSubjectDN().toString();
                if (clientIssuer.equals(caSubject)) {
                    certChainList.add(caCert);
                    Log.d(TAG, "  ✓ Found intermediate CA: " + caSubject);

                    // Check if this intermediate is issued by another CA (build full chain)
                    String caIssuer = caCert.getIssuerDN().toString();
                    if (!caSubject.equals(caIssuer)) { // Not self-signed
                        for (X509Certificate rootCaCert : caCertsList) {
                            if (caIssuer.equals(rootCaCert.getSubjectDN().toString())) {
                                certChainList.add(rootCaCert);
                                Log.d(TAG, "  ✓ Found root CA: " + rootCaCert.getSubjectDN());
                                break;
                            }
                        }
                    }
                    break;
                }
            }

            java.security.cert.Certificate[] certChain = certChainList.toArray(new java.security.cert.Certificate[0]);
            Log.i(TAG, "");
            Log.i(TAG, "✓✓✓ Certificate chain built with " + certChain.length + " certificate(s)");
            for (int i = 0; i < certChain.length; i++) {
                X509Certificate cert = (X509Certificate) certChain[i];
                Log.d(TAG, "  Chain[" + i + "]: " + cert.getSubjectDN());
            }

            // Step 5: Create KeyStore with private key from AndroidKeyStore
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 5: Creating KeyStore for SSL");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            Log.d(TAG, "  KeyStore type: PKCS12");
            keyStore.load(null, null);
            Log.d(TAG, "  ✓ KeyStore initialized");

            // Add the private key (from AndroidKeyStore) with the certificate chain
            keyStore.setKeyEntry("client-key", privateKey, "".toCharArray(), certChain);
            Log.d(TAG, "  ✓ Client private key added to KeyStore with " + certChain.length + "-cert chain");
            Log.d(TAG, "  ✓ Private key remains in AndroidKeyStore (hardware-backed)");

            // Step 6: Initialize KeyManagerFactory
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 6: Initializing KeyManagerFactory");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            Log.d(TAG, "  KeyManagerFactory algorithm: " + kmf.getAlgorithm());
            kmf.init(keyStore, "".toCharArray());
            Log.i(TAG, "  ✓ KeyManagerFactory initialized successfully");

            // Step 7: Create TrustStore for CA certificate(s)
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 7: Creating TrustStore");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");

            KeyStore trustStore = KeyStore.getInstance("PKCS12");
            Log.d(TAG, "  TrustStore type: PKCS12");
            trustStore.load(null, null);
            Log.d(TAG, "  ✓ TrustStore initialized");

            // Add ALL CA certificates to TrustStore
            certIndex = 0;
            for (java.security.cert.Certificate cert : caCerts) {
                trustStore.setCertificateEntry("ca-" + certIndex, cert);
                Log.d(TAG, "  ✓ CA certificate #" + certIndex + " added to TrustStore");
                certIndex++;
            }
            Log.i(TAG, "  ✓✓✓ All " + caCerts.size() + " CA certificate(s) added to TrustStore");

            // Step 8: Initialize TrustManagerFactory
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 8: Initializing TrustManagerFactory");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            Log.d(TAG, "  TrustManagerFactory algorithm: " + tmf.getAlgorithm());
            tmf.init(trustStore);
            Log.i(TAG, "  ✓ TrustManagerFactory initialized successfully");

            // Step 9: Create SSLContext with TLS
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 9: Creating SSLContext");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");

            SSLContext sslContext = SSLContext.getInstance("TLS");
            Log.d(TAG, "  SSLContext protocol: " + sslContext.getProtocol());
            Log.d(TAG, "  SSLContext provider: " + sslContext.getProvider().getName());
            Log.d(TAG, "  SSLContext provider version: " + sslContext.getProvider().getVersion());

            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            Log.i(TAG, "");
            Log.i(TAG, "✓✓✓ SSLContext Created Successfully with AndroidKeyStore ✓✓✓");

            // Log supported protocols and cipher suites
            try {
                String[] supportedProtocols = sslContext.getSupportedSSLParameters().getProtocols();
                Log.d(TAG, "  Supported SSL/TLS protocols: " + java.util.Arrays.toString(supportedProtocols));

                String[] defaultProtocols = sslContext.getDefaultSSLParameters().getProtocols();
                Log.d(TAG, "  Default SSL/TLS protocols: " + java.util.Arrays.toString(defaultProtocols));

                String[] cipherSuites = sslContext.getDefaultSSLParameters().getCipherSuites();
                Log.d(TAG, "  Number of default cipher suites: " + cipherSuites.length);
                Log.d(TAG, "  First 5 cipher suites: " + java.util.Arrays
                        .toString(java.util.Arrays.copyOfRange(cipherSuites, 0, Math.min(5, cipherSuites.length))));
            } catch (Exception e) {
                Log.w(TAG, "  ⚠️ Could not log SSL parameters: " + e.getMessage());
            }

            return sslContext;

        } catch (Exception e) {
            Log.e(TAG, "");
            Log.e(TAG, "╔════════════════════════════════════════════════════════════════");
            Log.e(TAG, "║ ❌❌❌ SSLContext Creation Failed");
            Log.e(TAG, "╠════════════════════════════════════════════════════════════════");
            Log.e(TAG, "║ Error type: " + e.getClass().getName());
            Log.e(TAG, "║ Error message: " + e.getMessage());
            Log.e(TAG, "║ Localized message: " + e.getLocalizedMessage());

            if (e.getCause() != null) {
                Log.e(TAG, "╠════════════════════════════════════════════════════════════════");
                Log.e(TAG, "║ Root Cause: " + e.getCause().getMessage());
                Log.e(TAG, "║ Cause type: " + e.getCause().getClass().getName());
            }
            Log.e(TAG, "╚════════════════════════════════════════════════════════════════");

            Log.e(TAG, "=== Full Stack Trace ===");
            e.printStackTrace();

            if (e.getCause() != null) {
                Log.e(TAG, "=== Root Cause Stack Trace ===");
                e.getCause().printStackTrace();
            }

            throw new Exception("Failed to create SSLContext: " + e.getMessage(), e);
        }
    }

    private void sendEvent(String eventName, String message) {
        reactContext
                .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)
                .emit(eventName, message);
    }
}

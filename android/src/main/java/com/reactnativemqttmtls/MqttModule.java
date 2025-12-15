package com.reactnativemqttmtls;

import android.content.Context;
import android.util.Log;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.modules.core.DeviceEventManagerModule;

//import org.eclipse.paho.android.service.MqttAndroidClient;
import info.mqtt.android.service.MqttAndroidClient;
import org.eclipse.paho.client.mqttv3.IMqttDeliveryToken;
import org.eclipse.paho.client.mqttv3.IMqttActionListener;
import org.eclipse.paho.client.mqttv3.IMqttToken;
import org.eclipse.paho.client.mqttv3.MqttCallbackExtended;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.MqttMessage;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.PrivateKey;
import java.security.Security;
import java.util.Collection;
import java.util.Collections;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.SNIHostName;

public class MqttModule extends ReactContextBaseJavaModule {
    private static final String TAG = "MqttModule";
    private final ReactApplicationContext reactContext;
    private MqttAndroidClient client;

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

    /**
     * Custom SSLSocketFactory that connects to a specific IP while preserving SNI hostname
     * This solves the DNS resolution issue when using .local hostnames
     */
    private static class SniIpSocketFactory extends SSLSocketFactory {
        private final SSLSocketFactory delegate;
        private final String sniHost;       // Broker hostname for SNI (must match broker cert SAN)
        private final String realIp;        // Actual broker IP address

        public SniIpSocketFactory(SSLSocketFactory delegate, String sniHost, String realIp) {
            this.delegate = delegate;
            this.sniHost = sniHost;
            this.realIp = realIp;
        }

        @Override
        public Socket createSocket() throws IOException {
            return delegate.createSocket();
        }

        @Override
        public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
            SSLSocket socket = (SSLSocket) delegate.createSocket(s, sniHost, port, autoClose);
            applySniAndSettings(socket);
            return socket;
        }

        @Override
        public Socket createSocket(String host, int port) throws IOException {
            SSLSocket socket = (SSLSocket) delegate.createSocket(realIp, port);
            applySniAndSettings(socket);
            return socket;
        }

        @Override
        public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
            SSLSocket socket = (SSLSocket) delegate.createSocket(realIp, port, localHost, localPort);
            applySniAndSettings(socket);
            return socket;
        }

        @Override
        public Socket createSocket(InetAddress host, int port) throws IOException {
            SSLSocket socket = (SSLSocket) delegate.createSocket(InetAddress.getByName(realIp), port);
            applySniAndSettings(socket);
            return socket;
        }

        @Override
        public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
            SSLSocket socket = (SSLSocket) delegate.createSocket(InetAddress.getByName(realIp), port, localAddress, localPort);
            applySniAndSettings(socket);
            return socket;
        }

        private void applySniAndSettings(SSLSocket socket) throws IOException {
            // Set SNI hostname explicitly
            SSLParameters params = socket.getSSLParameters();
            params.setServerNames(Collections.singletonList(new SNIHostName(sniHost)));
            socket.setSSLParameters(params);

            // Force modern TLS versions
            socket.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
            
            Log.d(TAG, "  ✓ SNI configured: " + sniHost);
            Log.d(TAG, "  ✓ Connecting to IP: " + realIp);
        }

        @Override 
        public String[] getDefaultCipherSuites() { 
            return delegate.getDefaultCipherSuites(); 
        }
        
        @Override 
        public String[] getSupportedCipherSuites() { 
            return delegate.getSupportedCipherSuites(); 
        }
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
            String rootCaPem = certificates.hasKey("rootCa")
                    ? sanitizePEM(certificates.getString("rootCa"), "Root CA")
                    : null;

            // Extract SNI hostname and broker IP from certificates map (optional)
            String sniHostname = certificates.hasKey("sniHostname") 
                    ? certificates.getString("sniHostname") 
                    : null;
            String brokerIp = certificates.hasKey("brokerIp") 
                    ? certificates.getString("brokerIp") 
                    : null;

            // Validate that all required parameters are provided
            if (clientCertPem == null || privateKeyAlias == null || rootCaPem == null) {
                String error = "Missing required parameters. Please provide clientCert, privateKeyAlias, and rootCa.";
                Log.e(TAG, "❌ " + error);
                Log.e(TAG, "  clientCert provided: " + (clientCertPem != null));
                Log.e(TAG, "  privateKeyAlias provided: " + (privateKeyAlias != null));
                Log.e(TAG, "  rootCa provided: " + (rootCaPem != null));
                errorCallback.invoke(error);
                return;
            }

            Log.i(TAG, "✓ All required parameters provided");
            Log.d(TAG, "  Client cert length: " + clientCertPem.length() + " bytes");
            Log.d(TAG, "  Private key alias: " + privateKeyAlias);
            Log.d(TAG, "  Root CA length: " + rootCaPem.length() + " bytes");
            
            if (sniHostname != null && brokerIp != null) {
                Log.i(TAG, "✓ SNI configuration provided");
                Log.d(TAG, "  SNI Hostname: " + sniHostname);
                Log.d(TAG, "  Broker IP: " + brokerIp);
            } else {
                Log.i(TAG, "⚠️ No SNI configuration provided - will use standard connection");
                Log.d(TAG, "  sniHostname provided: " + (sniHostname != null));
                Log.d(TAG, "  brokerIp provided: " + (brokerIp != null));
            }

            // Initialize MQTT Android client
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 1: Creating MQTT Android Client");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");
            client = new MqttAndroidClient(reactContext, broker, clientId);
            Log.i(TAG, "✓ MQTT Android client created successfully");

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

            // Create SSL context with hardware-backed private key
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 3: Creating SSL Context with Hardware Key");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");

            SSLContext sslContext = createSSLContextWithHardwareKey(privateKeyAlias, clientCertPem, rootCaPem);

            // Configure socket factory based on whether SNI configuration is provided
            if (sniHostname != null && brokerIp != null) {
                Log.d(TAG, "");
                Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
                Log.d(TAG, "│ Step 3.5: Configuring SNI Socket Factory");
                Log.d(TAG, "└─────────────────────────────────────────────────────────────");
                Log.d(TAG, "  SNI Hostname: " + sniHostname);
                Log.d(TAG, "  Real IP: " + brokerIp);
                
                SSLSocketFactory baseFactory = sslContext.getSocketFactory();
                SSLSocketFactory customFactory = new SniIpSocketFactory(baseFactory, sniHostname, brokerIp);
                
                options.setSocketFactory(customFactory);
                Log.i(TAG, "✓ Custom SNI socket factory configured");
                Log.i(TAG, "  ✓ DNS resolution bypassed - connecting directly to IP");
                Log.i(TAG, "  ✓ SNI hostname preserved for certificate validation");
            } else {
                Log.d(TAG, "");
                Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
                Log.d(TAG, "│ Step 3.5: Configuring Standard SSL Socket Factory");
                Log.d(TAG, "└─────────────────────────────────────────────────────────────");
                
                options.setSocketFactory(sslContext.getSocketFactory());
                Log.i(TAG, "✓ Standard SSL socket factory configured");
                Log.i(TAG, "  ✓ Using standard DNS resolution");
            }

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
            Log.d(TAG, "║ Broker: " + broker);
            Log.d(TAG, "║ Client ID: " + clientId);
            Log.d(TAG, "╚════════════════════════════════════════════════════════════════");

            client.connect(options, null, new IMqttActionListener() {
                @Override
                public void onSuccess(IMqttToken asyncActionToken) {
                    Log.i(TAG, "");
                    Log.i(TAG, "╔════════════════════════════════════════════════════════════════");
                    Log.i(TAG, "║ ✓✓✓ MQTT CLIENT SUCCESSFULLY CONNECTED ✓✓✓");
                    Log.i(TAG, "╠════════════════════════════════════════════════════════════════");
                    Log.i(TAG, "║ Broker: " + broker);
                    Log.i(TAG, "║ Client ID: " + clientId);
                    Log.i(TAG, "║ Connection established at: " + new java.util.Date().toString());
                    Log.i(TAG, "╚════════════════════════════════════════════════════════════════");
                    
                    successCallback.invoke("Connected to " + broker);
                }

                @Override
                public void onFailure(IMqttToken asyncActionToken, Throwable exception) {
                    Log.e(TAG, "");
                    Log.e(TAG, "╔════════════════════════════════════════════════════════════════");
                    Log.e(TAG, "║ ❌❌❌ MQTT CONNECTION FAILED IN ASYNC CALLBACK");
                    Log.e(TAG, "╠════════════════════════════════════════════════════════════════");
                    Log.e(TAG, "║ Error: " + exception.getMessage());
                    Log.e(TAG, "║ Type: " + exception.getClass().getName());
                    Log.e(TAG, "║ Timestamp: " + new java.util.Date().toString());
                    
                    if (exception.getCause() != null) {
                        Log.e(TAG, "╠════════════════════════════════════════════════════════════════");
                        Log.e(TAG, "║ Root Cause: " + exception.getCause().getMessage());
                        Log.e(TAG, "║ Root Cause Type: " + exception.getCause().getClass().getName());
                    }
                    Log.e(TAG, "╚════════════════════════════════════════════════════════════════");
                    
                    Log.e(TAG, "=== Full Stack Trace ===");
                    exception.printStackTrace();
                    
                    if (exception.getCause() != null) {
                        Log.e(TAG, "=== Root Cause Stack Trace ===");
                        exception.getCause().printStackTrace();
                    }
                    
                    errorCallback.invoke("Connection failed: " + exception.getMessage());
                }
            });

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
                Log.e(TAG, "║ Root Cause Type: " + e.getCause().getClass().getName());
            }
            Log.e(TAG, "╚════════════════════════════════════════════════════════════════");

            Log.e(TAG, "=== Full Stack Trace ===");
            e.printStackTrace();

            if (e.getCause() != null) {
                Log.e(TAG, "=== Root Cause Stack Trace ===");
                e.getCause().printStackTrace();
            }

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

            client.subscribe(topic, qos, null, new IMqttActionListener() {
                @Override
                public void onSuccess(IMqttToken asyncActionToken) {
                    Log.i(TAG, "✓ Successfully subscribed to: " + topic);
                    successCallback.invoke("Subscribed to " + topic);
                }

                @Override
                public void onFailure(IMqttToken asyncActionToken, Throwable exception) {
                    Log.e(TAG, "❌ Subscribe failed: " + exception.getMessage());
                    exception.printStackTrace();
                    errorCallback.invoke("Subscribe failed: " + exception.getMessage());
                }
            });

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

            client.unsubscribe(topic, null, new IMqttActionListener() {
                @Override
                public void onSuccess(IMqttToken asyncActionToken) {
                    Log.i(TAG, "✓ Successfully unsubscribed from: " + topic);
                    successCallback.invoke("Unsubscribed from " + topic);
                }

                @Override
                public void onFailure(IMqttToken asyncActionToken, Throwable exception) {
                    Log.e(TAG, "❌ Unsubscribe failed: " + exception.getMessage());
                    exception.printStackTrace();
                    errorCallback.invoke("Unsubscribe failed: " + exception.getMessage());
                }
            });

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

            client.publish(topic, mqttMessage, null, new IMqttActionListener() {
                @Override
                public void onSuccess(IMqttToken asyncActionToken) {
                    Log.i(TAG, "✓ Message published successfully");
                    successCallback.invoke("Published to " + topic);
                }

                @Override
                public void onFailure(IMqttToken asyncActionToken, Throwable exception) {
                    Log.e(TAG, "❌ Publish failed: " + exception.getMessage());
                    exception.printStackTrace();
                    errorCallback.invoke("Publish failed: " + exception.getMessage());
                }
            });

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
                client.disconnect(null, new IMqttActionListener() {
                    @Override
                    public void onSuccess(IMqttToken asyncActionToken) {
                        Log.i(TAG, "✓ Disconnected from broker");
                        try {
                            client.close();
                            client = null;
                            Log.i(TAG, "✓ MQTT client closed");
                            successCallback.invoke("Disconnected successfully");
                        } catch (Exception e) {
                            Log.e(TAG, "❌ Error closing client: " + e.getMessage());
                            errorCallback.invoke("Disconnect error: " + e.getMessage());
                        }
                    }

                    @Override
                    public void onFailure(IMqttToken asyncActionToken, Throwable exception) {
                        Log.e(TAG, "❌ Disconnect failed: " + exception.getMessage());
                        exception.printStackTrace();
                        errorCallback.invoke("Disconnect failed: " + exception.getMessage());
                    }
                });
            } else {
                client.close();
                client = null;
                Log.i(TAG, "✓ MQTT client closed (was not connected)");
                successCallback.invoke("Disconnected successfully");
            }

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
     * Creates an SSLContext using hardware-backed private key and PEM certificates
     * 
     * @param privateKeyAlias The alias of the private key in Android KeyStore
     * @param clientCertPem   The client certificate in PEM format (can include intermediate certs)
     * @param rootCaPem       The root CA certificate(s) in PEM format
     * @return Configured SSLContext
     */
    private SSLContext createSSLContextWithHardwareKey(String privateKeyAlias, String clientCertPem, String rootCaPem)
            throws Exception {
        try {
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Creating SSLContext with Hardware-Backed Key");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");

            // Step 1: Load private key from Android KeyStore
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 1: Loading Private Key from Android KeyStore");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");

            KeyStore androidKeyStore = KeyStore.getInstance("AndroidKeyStore");
            androidKeyStore.load(null);
            Log.d(TAG, "  ✓ Android KeyStore loaded");

            PrivateKey privateKey = (PrivateKey) androidKeyStore.getKey(privateKeyAlias, null);
            
            if (privateKey == null) {
                throw new Exception("Private key not found in KeyStore with alias: " + privateKeyAlias);
            }

            Log.i(TAG, "  ✓✓✓ Private key retrieved from hardware");
            Log.d(TAG, "  Private key alias: " + privateKeyAlias);
            Log.d(TAG, "  Private key algorithm: " + privateKey.getAlgorithm());
            Log.d(TAG, "  Private key format: " + privateKey.getFormat());
            Log.d(TAG, "  Private key class: " + privateKey.getClass().getName());
            Log.d(TAG, "  Hardware-backed: " + isHardwareBacked(androidKeyStore, privateKeyAlias));

            // Step 2: Parse client certificate(s)
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 2: Parsing Client Certificate(s)");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            Log.d(TAG, "  Certificate factory type: " + certFactory.getType());
            Log.d(TAG, "  Certificate factory provider: " + certFactory.getProvider().getName());

            InputStream clientCertStream = new ByteArrayInputStream(clientCertPem.getBytes());
            Collection<? extends java.security.cert.Certificate> clientCerts = certFactory
                    .generateCertificates(clientCertStream);

            if (clientCerts.isEmpty()) {
                throw new Exception("No client certificate found in PEM");
            }

            Log.i(TAG, "  ✓ " + clientCerts.size() + " certificate(s) parsed from client cert file");

            // Convert to list
            ArrayList<X509Certificate> clientCertsList = new ArrayList<>();
            for (java.security.cert.Certificate cert : clientCerts) {
                clientCertsList.add((X509Certificate) cert);
            }

            // First certificate is the client certificate
            X509Certificate clientCert = clientCertsList.get(0);
            Log.i(TAG, "  ✓ Client certificate (leaf) parsed");
            Log.d(TAG, "  ═══ CLIENT CERTIFICATE DETAILS ═══");
            Log.d(TAG, "  Subject: " + clientCert.getSubjectDN());
            Log.d(TAG, "  Issuer: " + clientCert.getIssuerDN());
            Log.d(TAG, "  Serial: " + clientCert.getSerialNumber());
            Log.d(TAG, "  Valid from: " + clientCert.getNotBefore());
            Log.d(TAG, "  Valid until: " + clientCert.getNotAfter());
            Log.d(TAG, "  Signature algorithm: " + clientCert.getSigAlgName());
            Log.d(TAG, "  Public key algorithm: " + clientCert.getPublicKey().getAlgorithm());
            
            try {
                clientCert.checkValidity();
                Log.d(TAG, "  Certificate validity: ✓ VALID");
            } catch (Exception e) {
                Log.e(TAG, "  Certificate validity: ❌ INVALID - " + e.getMessage());
            }

            // Log intermediate certificates if present
            if (clientCertsList.size() > 1) {
                Log.i(TAG, "  ✓ " + (clientCertsList.size() - 1) + " intermediate certificate(s) found");
                for (int i = 1; i < clientCertsList.size(); i++) {
                    X509Certificate intermediateCert = clientCertsList.get(i);
                    Log.d(TAG, "  ═══ INTERMEDIATE CERTIFICATE #" + i + " ═══");
                    Log.d(TAG, "    Subject: " + intermediateCert.getSubjectDN());
                    Log.d(TAG, "    Issuer: " + intermediateCert.getIssuerDN());
                }
            }

            // Step 3: Parse CA certificates
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 3: Parsing Root CA Certificate(s)");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");

            InputStream caStream = new ByteArrayInputStream(rootCaPem.getBytes());
            Collection<? extends java.security.cert.Certificate> caCerts = certFactory.generateCertificates(caStream);

            if (caCerts.isEmpty()) {
                throw new Exception("No CA certificates found in PEM");
            }

            Log.i(TAG, "  ✓ " + caCerts.size() + " root CA certificate(s) parsed");

            int certIndex = 0;
            for (java.security.cert.Certificate cert : caCerts) {
                X509Certificate caCert = (X509Certificate) cert;
                Log.d(TAG, "  ═══ ROOT CA CERTIFICATE #" + certIndex + " ═══");
                Log.d(TAG, "    Subject: " + caCert.getSubjectDN());
                Log.d(TAG, "    Issuer: " + caCert.getIssuerDN());
                Log.d(TAG, "    Is self-signed: " + caCert.getIssuerDN().equals(caCert.getSubjectDN()));
                
                try {
                    caCert.checkValidity();
                    Log.d(TAG, "    Certificate validity: ✓ VALID");
                } catch (Exception e) {
                    Log.e(TAG, "    Certificate validity: ❌ INVALID - " + e.getMessage());
                }
                
                certIndex++;
            }

            // Step 4: Build certificate chain (client + intermediates, excluding root)
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 4: Building Certificate Chain");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");

            ArrayList<java.security.cert.Certificate> certChainList = new ArrayList<>();

            // Add non-self-signed certificates only
            for (X509Certificate cert : clientCertsList) {
                boolean isSelfSigned = cert.getIssuerDN().equals(cert.getSubjectDN());
                
                if (!isSelfSigned) {
                    certChainList.add(cert);
                    Log.d(TAG, "  ✓ Added to chain: " + cert.getSubjectDN());
                } else {
                    Log.d(TAG, "  ⊗ Excluded root CA from chain: " + cert.getSubjectDN());
                }
            }

            java.security.cert.Certificate[] certChain = certChainList.toArray(new java.security.cert.Certificate[0]);
            Log.i(TAG, "");
            Log.i(TAG, "✓✓✓ Certificate chain built with " + certChain.length + " certificate(s)");

            // Step 5: Create KeyStore with hardware-backed private key
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 5: Creating KeyStore for SSL");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            Log.d(TAG, "  KeyStore type: " + keyStore.getType());
            keyStore.load(null, null);
            Log.d(TAG, "  ✓ KeyStore initialized");

            keyStore.setKeyEntry("client-key", privateKey, "".toCharArray(), certChain);
            Log.d(TAG, "  ✓ Hardware-backed private key and certificate chain added to KeyStore");

            // Step 6: Initialize KeyManagerFactory
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 6: Initializing KeyManagerFactory");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, "".toCharArray());
            Log.i(TAG, "  ✓ KeyManagerFactory initialized successfully");

            // Step 7: Create TrustStore
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 7: Creating TrustStore");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");

            KeyStore trustStore = KeyStore.getInstance("PKCS12");
            trustStore.load(null, null);
            Log.d(TAG, "  ✓ TrustStore initialized");

            certIndex = 0;
            for (java.security.cert.Certificate cert : caCerts) {
                trustStore.setCertificateEntry("ca-" + certIndex, cert);
                Log.d(TAG, "  ✓ CA certificate #" + certIndex + " added");
                certIndex++;
            }
            Log.i(TAG, "  ✓✓✓ All " + caCerts.size() + " CA certificate(s) added to TrustStore");

            // Step 8: Initialize TrustManagerFactory
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 8: Initializing TrustManagerFactory");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            Log.i(TAG, "  ✓ TrustManagerFactory initialized successfully");

            // Step 9: Create SSLContext
            Log.d(TAG, "");
            Log.d(TAG, "┌─────────────────────────────────────────────────────────────");
            Log.d(TAG, "│ Step 9: Creating SSLContext");
            Log.d(TAG, "└─────────────────────────────────────────────────────────────");

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            
            Log.i(TAG, "");
            Log.i(TAG, "✓✓✓ SSLContext Created Successfully with Hardware-Backed Key ✓✓✓");

            return sslContext;

        } catch (Exception e) {
            Log.e(TAG, "");
            Log.e(TAG, "╔════════════════════════════════════════════════════════════════");
            Log.e(TAG, "║ ❌❌❌ SSLContext Creation Failed");
            Log.e(TAG, "╠════════════════════════════════════════════════════════════════");
            Log.e(TAG, "║ Error: " + e.getMessage());
            Log.e(TAG, "║ Type: " + e.getClass().getName());
            
            if (e.getCause() != null) {
                Log.e(TAG, "╠════════════════════════════════════════════════════════════════");
                Log.e(TAG, "║ Root Cause: " + e.getCause().getMessage());
            }
            Log.e(TAG, "╚════════════════════════════════════════════════════════════════");

            e.printStackTrace();
            throw new Exception("Failed to create SSLContext: " + e.getMessage(), e);
        }
    }

    /**
     * Checks if a key in the KeyStore is backed by hardware
     */
    private boolean isHardwareBacked(KeyStore keyStore, String alias) {
        try {
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
                PrivateKey key = (PrivateKey) keyStore.getKey(alias, null);
                if (key instanceof java.security.interfaces.RSAKey) {
                    // Check if key is inside secure hardware
                    android.security.keystore.KeyInfo keyInfo;
                    try {
                        java.security.KeyFactory factory = java.security.KeyFactory.getInstance(
                            key.getAlgorithm(), "AndroidKeyStore");
                        keyInfo = factory.getKeySpec(key, android.security.keystore.KeyInfo.class);
                        return keyInfo.isInsideSecureHardware();
                    } catch (Exception e) {
                        Log.w(TAG, "Could not determine if key is hardware-backed: " + e.getMessage());
                        return false;
                    }
                }
            }
            return false;
        } catch (Exception e) {
            Log.w(TAG, "Error checking hardware backing: " + e.getMessage());
            return false;
        }
    }

    private void sendEvent(String eventName, String message) {
        reactContext
                .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)
                .emit(eventName, message);
    }
}

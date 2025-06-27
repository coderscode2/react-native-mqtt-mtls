package com.reactnativemqttmtls.mqtt;

import android.content.Context;
import android.util.Log;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Callback;
import com.facebook.react.modules.core.DeviceEventManagerModule;

import org.eclipse.paho.client.mqttv3.IMqttDeliveryToken;
import org.eclipse.paho.client.mqttv3.MqttCallbackExtended;
import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.MqttMessage;
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

public class MqttModule extends ReactContextBaseJavaModule {
    private static final String TAG = "MqttModule";
    private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    private static final String KEY_ALIAS = "GENERAC_PWRVIEW_ECC_KEY_ALIAS";
    private static final String CLIENT_CERT_ALIAS = "clientCert";
    private static final String ROOT_CA_ALIAS = "rootCa";
    private final ReactApplicationContext reactContext;
    private MqttClient client;

    public MqttModule(ReactApplicationContext reactContext) {
        super(reactContext);
        this.reactContext = reactContext;
    }

    @Override
    public String getName() {
        return "MqttModule";
    }

    @ReactMethod
    public void connect(String broker, String clientId, Callback successCallback, Callback errorCallback) {
        try {
            client = new MqttClient(broker, clientId, new MemoryPersistence());
            MqttConnectOptions options = new MqttConnectOptions();
            options.setCleanSession(true);

            SSLContext sslContext = createSslContext();
            options.setSocketFactory(sslContext.getSocketFactory());

            client.setCallback(new MqttCallbackExtended() {
                @Override
                public void connectComplete(boolean reconnect, String serverURI) {
                    Log.d(TAG, "Connected to: " + serverURI);
                    sendEvent("MqttConnect", "Connected");
                }

                @Override
                public void connectionLost(Throwable cause) {
                    Log.e(TAG, "Connection lost: " + cause.getMessage());
                    sendEvent("MqttConnectionLost", cause.getMessage());
                }

                @Override
                public void messageArrived(String topic, MqttMessage message) {
                    String payload = new String(message.getPayload());
                    Log.d(TAG, "Message arrived: " + topic + " -> " + payload);
                    sendEvent("MqttMessage", topic + ":" + payload);
                }

                @Override
                public void deliveryComplete(IMqttDeliveryToken token) {
                    Log.d(TAG, "Message delivered");
                }
            });

            client.connect(options);
            successCallback.invoke("Connected to " + broker);
        } catch (Exception e) {
            Log.e(TAG, "Connection error: " + e.getMessage());
            errorCallback.invoke(e.getMessage());
        }
    }

    @ReactMethod
    public void subscribe(String topic, int qos) {
        try {
            if (client != null && client.isConnected()) {
                client.subscribe(topic, qos);
                Log.d(TAG, "Subscribed to: " + topic);
            } else {
                Log.e(TAG, "Cannot subscribe: Client not connected");
            }
        } catch (MqttException e) {
            Log.e(TAG, "Subscribe error: " + e.getMessage());
        }
    }

    @ReactMethod
    public void publish(String topic, String message, int qos, boolean retained) {
        try {
            if (client != null && client.isConnected()) {
                MqttMessage mqttMessage = new MqttMessage(message.getBytes());
                mqttMessage.setQos(qos);
                mqttMessage.setRetained(retained);
                client.publish(topic, mqttMessage);
                Log.d(TAG, "Published to: " + topic);
            } else {
                Log.e(TAG, "Cannot publish: Client not connected");
            }
        } catch (MqttException e) {
            Log.e(TAG, "Publish error: " + e.getMessage());
        }
    }

    @ReactMethod
    public void disconnect(Callback callback) {
        try {
            if (client != null && client.isConnected()) {
                client.disconnect();
                Log.d(TAG, "Disconnected");
                callback.invoke("Disconnected");
            }
        } catch (MqttException e) {
            Log.e(TAG, "Disconnect error: " + e.getMessage());
            callback.invoke(e.getMessage());
        }
    }

    private SSLContext createSslContext() throws Exception {
        try {
            // Load AndroidKeyStore
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null, null);

            // Retrieve client certificate
            X509Certificate clientCert = (X509Certificate) keyStore.getCertificate(CLIENT_CERT_ALIAS);
            if (clientCert == null) {
                throw new Exception("Client certificate not found in KeyStore");
            }

            // Retrieve private key
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, null);
            if (privateKey == null) {
                throw new Exception("Private key not found in KeyStore");
            }

            // Retrieve root CA certificate
            X509Certificate caCert = (X509Certificate) keyStore.getCertificate(ROOT_CA_ALIAS);
            if (caCert == null) {
                throw new Exception("Root CA certificate not found in KeyStore");
            }

            // Create KeyStore for client certificate and private key
            KeyStore pkcs12KeyStore = KeyStore.getInstance("PKCS12");
            pkcs12KeyStore.load(null, null);
            pkcs12KeyStore.setKeyEntry("client", privateKey, null, new java.security.cert.Certificate[]{clientCert});

            // Initialize KeyManagerFactory
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(pkcs12KeyStore, null);

            // Create TrustStore for CA certificate
            KeyStore trustStore = KeyStore.getInstance("PKCS12");
            trustStore.load(null, null);
            trustStore.setCertificateEntry("ca", caCert);

            // Initialize TrustManagerFactory
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            // Create SSLContext
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            return sslContext;
        } catch (Exception e) {
            Log.e(TAG, "SSLContext creation error: " + e.getMessage());
            throw new Exception("Failed to create SSLContext: " + e.getMessage(), e);
        }
    }

    private void sendEvent(String eventName, String message) {
        reactContext
                .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)
                .emit(eventName, message);
    }
}
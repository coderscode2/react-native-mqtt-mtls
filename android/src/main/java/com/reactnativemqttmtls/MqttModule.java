package com.reactnativemqttmtls;

import android.util.Log;
import androidx.annotation.NonNull;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;
import info.mqtt.android.service.MqttAndroidClient;
import org.eclipse.paho.client.mqttv3.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import javax.net.ssl.*;

public class MqttModule extends ReactContextBaseJavaModule {
    private static final String TAG = "MqttModule";

    public MqttModule(ReactApplicationContext reactContext) {
        super(reactContext);
        setupBouncyCastle();
    }

    private void setupBouncyCastle() {
        try {
            Security.removeProvider("BC");
            Security.addProvider(new BouncyCastleProvider());
            Log.d(TAG, "✓ BouncyCastle Provider initialized");
        } catch (Exception e) {
            Log.e(TAG, "Failed to register BC provider", e);
        }
    }

    @NonNull
    @Override
    public String getName() {
        return "MqttModule";
    }

    // --- Helper Methods ---
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    private void verifyCertMatchesKey(X509Certificate cert, String privateKeyAlias, KeyStore keyStore)
            throws Exception {
        Log.d(TAG, "→ Verifying certificate matches private key...");

        // Get the public key from the certificate
        PublicKey certPublicKey = cert.getPublicKey();

        // Get the public key from the keystore
        KeyStore.Entry entry = keyStore.getEntry(privateKeyAlias, null);
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            throw new KeyException("Not a private key entry");
        }

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
        PublicKey keystorePublicKey = privateKeyEntry.getCertificate().getPublicKey();

        // Compare the encoded forms
        byte[] certPubBytes = certPublicKey.getEncoded();
        byte[] keystorePubBytes = keystorePublicKey.getEncoded();

        Log.d(TAG, "Cert public key (first 32 bytes): "
                + bytesToHex(Arrays.copyOf(certPubBytes, Math.min(32, certPubBytes.length))));
        Log.d(TAG, "Keystore public key (first 32 bytes): "
                + bytesToHex(Arrays.copyOf(keystorePubBytes, Math.min(32, keystorePubBytes.length))));

        if (!Arrays.equals(certPubBytes, keystorePubBytes)) {
            Log.e(TAG, "❌❌❌ CERTIFICATE PUBLIC KEY DOES NOT MATCH PRIVATE KEY! ❌❌❌");
            Log.e(TAG, "You are using the WRONG certificate for this private key!");
            Log.e(TAG, "You must get a NEW certificate for the CSR generated with this key!");
            throw new KeyException("Certificate does not match the private key in keystore!");
        }

        Log.d(TAG, "✅ Certificate public key MATCHES private key");
    }

    // --- Diagnostic Methods ---
    @ReactMethod
    public void diagnoseKeyPurposes(String privateKeyAlias, Callback callback) {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            if (!keyStore.containsAlias(privateKeyAlias)) {
                callback.invoke("ERROR: Key not found: " + privateKeyAlias);
                return;
            }

            KeyStore.Entry entry = keyStore.getEntry(privateKeyAlias, null);
            if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
                callback.invoke("ERROR: Not a private key entry");
                return;
            }

            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
            PrivateKey privateKey = privateKeyEntry.getPrivateKey();

            StringBuilder result = new StringBuilder();
            result.append("=== Key Purposes for: ").append(privateKeyAlias).append(" ===\n\n");

            try {
                KeyFactory factory = KeyFactory.getInstance(
                        privateKey.getAlgorithm(),
                        "AndroidKeyStore");
                android.security.keystore.KeyInfo keyInfo = factory.getKeySpec(
                        privateKey,
                        android.security.keystore.KeyInfo.class);

                int purposes = keyInfo.getPurposes();
                result.append("Raw purposes value: ").append(purposes).append("\n\n");

                result.append("Key Purposes:\n");
                boolean hasSign = (purposes & android.security.keystore.KeyProperties.PURPOSE_SIGN) != 0;
                boolean hasVerify = (purposes & android.security.keystore.KeyProperties.PURPOSE_VERIFY) != 0;
                boolean hasAgreeKey = (purposes & android.security.keystore.KeyProperties.PURPOSE_AGREE_KEY) != 0;

                result.append("  SIGN: ").append(hasSign ? "✓ YES" : "✗ NO").append("\n");
                result.append("  VERIFY: ").append(hasVerify ? "✓ YES" : "✗ NO").append("\n");
                result.append("  AGREE_KEY: ").append(hasAgreeKey ? "✓ YES" : "✗ NO").append("\n\n");

                if (!hasAgreeKey) {
                    result.append("❌ PROBLEM FOUND!\n");
                    result.append("This key is MISSING PURPOSE_AGREE_KEY!\n");
                    result.append("TLS with ECC requires AGREE_KEY for ECDH.\n\n");
                    result.append("Solution:\n");
                    result.append("1. Delete this key\n");
                    result.append("2. Generate a new key with updated CSRModule.java\n");
                    result.append("3. Get a new certificate\n");
                } else {
                    result.append("✅ Key has all required purposes for TLS!\n");
                }

                result.append("\nOther Info:\n");
                result.append("  Key Size: ").append(keyInfo.getKeySize()).append(" bits\n");
                result.append("  Hardware-backed: ").append(keyInfo.isInsideSecureHardware()).append("\n");

            } catch (Exception e) {
                result.append("ERROR getting KeyInfo: ").append(e.getMessage()).append("\n");
                e.printStackTrace();
            }

            Log.d(TAG, result.toString());
            callback.invoke(result.toString());

        } catch (Exception e) {
            String error = "Diagnostic error: " + e.getMessage();
            Log.e(TAG, error, e);
            callback.invoke("ERROR: " + error);
        }
    }

    @ReactMethod
    public void verifyKeyCertMatch(String privateKeyAlias, String clientCertPem, Callback callback) {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            if (!keyStore.containsAlias(privateKeyAlias)) {
                callback.invoke("ERROR: Key not found: " + privateKeyAlias);
                return;
            }

            KeyStore.Entry entry = keyStore.getEntry(privateKeyAlias, null);
            if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
                callback.invoke("ERROR: Not a private key entry");
                return;
            }

            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
            PublicKey keystorePublicKey = privateKeyEntry.getCertificate().getPublicKey();

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Collection<? extends java.security.cert.Certificate> clientCerts = cf.generateCertificates(
                    new ByteArrayInputStream(clientCertPem.getBytes()));

            // Get the first cert (the actual client cert)
            X509Certificate clientCert = (X509Certificate) clientCerts.iterator().next();
            PublicKey certPublicKey = clientCert.getPublicKey();

            StringBuilder result = new StringBuilder();
            result.append("=== Key-Certificate Verification ===\n\n");

            boolean match = Arrays.equals(keystorePublicKey.getEncoded(), certPublicKey.getEncoded());

            if (match) {
                result.append("✅ SUCCESS: Public keys MATCH!\n");
                result.append("The certificate matches the private key.\n\n");
            } else {
                result.append("❌ ERROR: Public keys DO NOT MATCH!\n");
                result.append("The certificate does not match the private key.\n");
                result.append("You need to generate a NEW certificate for the NEW key.\n\n");
            }

            result.append("Keystore Public Key (first 20 bytes):\n");
            byte[] ksBytes = keystorePublicKey.getEncoded();
            result.append(bytesToHex(Arrays.copyOf(ksBytes, Math.min(20, ksBytes.length)))).append("...\n\n");

            result.append("Certificate Public Key (first 20 bytes):\n");
            byte[] certBytes = certPublicKey.getEncoded();
            result.append(bytesToHex(Arrays.copyOf(certBytes, Math.min(20, certBytes.length)))).append("...\n\n");

            result.append("Certificate Details:\n");
            result.append("Subject: ").append(clientCert.getSubjectDN()).append("\n");
            result.append("Issuer: ").append(clientCert.getIssuerDN()).append("\n");
            result.append("Valid From: ").append(clientCert.getNotBefore()).append("\n");
            result.append("Valid To: ").append(clientCert.getNotAfter()).append("\n");

            Log.d(TAG, result.toString());
            callback.invoke(result.toString());

        } catch (Exception e) {
            String error = "Verification error: " + e.getMessage();
            Log.e(TAG, error, e);
            callback.invoke("ERROR: " + error);
        }
    }

    // --- mTLS Helper Classes ---
    private static class AndroidKeystoreKeyManager implements X509KeyManager {
        private final String privateKeyAlias;
        private final KeyStore keyStore;
        private final X509Certificate[] chain;

        public AndroidKeystoreKeyManager(String privateKeyAlias, KeyStore keyStore, X509Certificate[] chain) {
            this.privateKeyAlias = privateKeyAlias;
            this.keyStore = keyStore;
            this.chain = chain;
        }

        @Override
        public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
            Log.d(TAG, "▶ chooseClientAlias called");
            Log.d(TAG, "  Key types: " + Arrays.toString(keyTypes));
            Log.d(TAG, "  Issuers: " + (issuers != null ? issuers.length : 0));
            return privateKeyAlias;
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            Log.d(TAG, "▶ getCertificateChain called");
            if (chain != null && chain.length > 0) {
                Log.d(TAG, "  Returning " + chain.length + " cert(s) in chain");
                for (int i = 0; i < chain.length; i++) {
                    Log.d(TAG, "    [" + i + "]: " + chain[i].getSubjectDN());
                }
            }
            return chain;
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            try {
                Log.d(TAG, "▶ getPrivateKey called");
                Key key = keyStore.getKey(this.privateKeyAlias, null);
                if (key == null) {
                    Log.e(TAG, "  ❌ Key is null!");
                    return null;
                }
                Log.d(TAG, "  ✓ Key retrieved: " + key.getClass().getSimpleName());
                return (PrivateKey) key;
            } catch (Exception e) {
                Log.e(TAG, "  ❌ Exception", e);
                return null;
            }
        }

        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return new String[] { privateKeyAlias };
        }

        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return null;
        }

        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            return null;
        }
    }

    private static class SniSocketFactory extends SSLSocketFactory {
        private final SSLSocketFactory delegate;
        private final String sniHost;

        public SniSocketFactory(SSLSocketFactory delegate, String sniHost) {
            this.delegate = delegate;
            this.sniHost = sniHost;
            Log.d(TAG, "▶▶▶ SniSocketFactory CONSTRUCTOR - SNI: " + sniHost);
        }

        @Override
        public Socket createSocket(Socket s, String h, int p, boolean a) throws IOException {
            Log.d(TAG, "▶▶▶ createSocket(Socket, String, int, boolean) CALLED ◀◀◀");
            Log.d(TAG, "  Host: " + h + ", Port: " + p + ", SNI: " + sniHost);

            String effectiveHost = (sniHost != null && !sniHost.isEmpty()) ? sniHost : h;
            SSLSocket ssl = (SSLSocket) delegate.createSocket(s, effectiveHost, p, a);

            if (sniHost != null && !sniHost.isEmpty()) {
                SSLParameters params = ssl.getSSLParameters();
                params.setServerNames(Collections.singletonList(new SNIHostName(sniHost)));
                ssl.setSSLParameters(params);
                Log.d(TAG, "  ✓ SNI set to: " + sniHost);
            } else {
                Log.d(TAG, "  ⚠ No SNI set");
            }

            Log.d(TAG, "  Protocols: " + Arrays.toString(ssl.getEnabledProtocols()));
            return ssl;
        }

        @Override
        public Socket createSocket() throws IOException {
            Log.d(TAG, "▶▶▶ createSocket() CALLED");
            return delegate.createSocket();
        }

        @Override
        public Socket createSocket(String h, int p) throws IOException {
            Log.d(TAG, "▶▶▶ createSocket(String, int) CALLED - " + h + ":" + p);
            return delegate.createSocket(h, p);
        }

        @Override
        public Socket createSocket(String h, int p, InetAddress l, int lp) throws IOException {
            Log.d(TAG, "▶▶▶ createSocket(String, int, InetAddress, int) CALLED");
            return delegate.createSocket(h, p, l, lp);
        }

        @Override
        public Socket createSocket(InetAddress a, int p) throws IOException {
            Log.d(TAG, "▶▶▶ createSocket(InetAddress, int) CALLED");
            return delegate.createSocket(a, p);
        }

        @Override
        public Socket createSocket(InetAddress a, int p, InetAddress l, int lp) throws IOException {
            Log.d(TAG, "▶▶▶ createSocket(InetAddress, int, InetAddress, int) CALLED");
            return delegate.createSocket(a, p, l, lp);
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

    // --- Main Connect Method ---
    @ReactMethod
    public void connect(
            String brokerUrl,
            String clientId,
            ReadableMap certificates,
            String sniHost,
            String brokerIp,
            final Callback success,
            final Callback error) {
        try {
            String privateKeyAlias = certificates.hasKey("privateKeyAlias")
                    ? certificates.getString("privateKeyAlias")
                    : null;

            if (privateKeyAlias == null || privateKeyAlias.isEmpty()) {
                throw new IllegalArgumentException("privateKeyAlias required");
            }

            Log.i(TAG, "========================================");
            Log.i(TAG, "MQTT Connection Attempt");
            Log.i(TAG, "Broker: " + brokerUrl);
            Log.i(TAG, "Broker IP: " + brokerIp);
            Log.i(TAG, "SNI: " + sniHost);
            Log.i(TAG, "Client ID: " + clientId);
            Log.i(TAG, "Key Alias: " + privateKeyAlias);
            Log.i(TAG, "========================================");

            MqttAndroidClient client = new MqttAndroidClient(
                    getReactApplicationContext(),
                    brokerUrl,
                    clientId);

            MqttConnectOptions options = new MqttConnectOptions();
            options.setCleanSession(true);
            options.setConnectionTimeout(30);
            options.setKeepAliveInterval(60);

            SSLContext sslContext = createSSLContextFromKeystore(
                    certificates.getString("clientCert"),
                    certificates.getString("rootCa"),
                    privateKeyAlias);

            SSLSocketFactory socketFactory;
            if (sniHost != null && !sniHost.isEmpty()) {
                socketFactory = new SniSocketFactory(sslContext.getSocketFactory(), sniHost);
                Log.d(TAG, "✓ Created SniSocketFactory");
            } else {
                socketFactory = sslContext.getSocketFactory();
                Log.d(TAG, "✓ Using default factory (no SNI)");
            }

            Log.d(TAG, "Socket factory class: " + socketFactory.getClass().getName());
            options.setSocketFactory(socketFactory);
            Log.d(TAG, "✓ Socket factory SET on MqttConnectOptions");

            // Verify it was set
            SSLSocketFactory verifyFactory = (SSLSocketFactory) options.getSocketFactory();
            Log.d(TAG, "Verified factory: " + (verifyFactory != null ? verifyFactory.getClass().getName() : "NULL"));
            Log.d(TAG, "Is SniSocketFactory? " + (verifyFactory instanceof SniSocketFactory));

            client.connect(options, null, new IMqttActionListener() {
                @Override
                public void onSuccess(IMqttToken asyncActionToken) {
                    Log.i(TAG, "✅✅✅ SUCCESS! MQTT CONNECTED! ✅✅✅");
                    if (success != null)
                        success.invoke("Connected");
                }

                @Override
                public void onFailure(IMqttToken asyncActionToken, Throwable exception) {
                    Log.e(TAG, "❌ MQTT Connection FAILED");
                    if (exception != null) {
                        Log.e(TAG, "Error: " + exception.getMessage());
                        exception.printStackTrace();
                    }
                    if (error != null)
                        error.invoke(exception != null ? exception.getMessage() : "Unknown");
                }
            });
        } catch (Exception e) {
            Log.e(TAG, "❌ Setup Error", e);
            if (error != null)
                error.invoke(e.getMessage());
        }
    }

    private SSLContext createSSLContextFromKeystore(
            String clientPem,
            String rootPem,
            String privateKeyAlias) throws Exception {
        Log.d(TAG, "→ Creating SSLContext for: " + privateKeyAlias);

        KeyStore androidKeyStore = KeyStore.getInstance("AndroidKeyStore");
        androidKeyStore.load(null);

        if (!androidKeyStore.containsAlias(privateKeyAlias)) {
            throw new KeyException("Key not found: " + privateKeyAlias);
        }
        Log.d(TAG, "✓ Key found in keystore");

        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        // Load client certificate CHAIN (can be multiple certificates)
        Collection<? extends java.security.cert.Certificate> clientCertChain = cf.generateCertificates(
                new ByteArrayInputStream(clientPem.getBytes()));
        Log.d(TAG, "✓ Loaded " + clientCertChain.size() + " client certificate(s)");

        // Convert to X509Certificate array
        X509Certificate[] clientCertArray = clientCertChain.toArray(new X509Certificate[0]);

        // Log each client cert in the chain
        for (int i = 0; i < clientCertArray.length; i++) {
            Log.d(TAG, "  Client[" + i + "]: " + clientCertArray[i].getSubjectDN());
        }

        // The FIRST certificate in the chain should be the actual client certificate
        X509Certificate clientCert = clientCertArray[0];

        // Load ALL CA certificates (multiple certs in one PEM string)
        Collection<? extends java.security.cert.Certificate> caCerts = cf.generateCertificates(
                new ByteArrayInputStream(rootPem.getBytes()));
        Log.d(TAG, "✓ Loaded " + caCerts.size() + " CA certificate(s)");

        // Log each CA cert
        int certNum = 0;
        for (java.security.cert.Certificate cert : caCerts) {
            X509Certificate x509 = (X509Certificate) cert;
            Log.d(TAG, "  CA[" + certNum + "]: " + x509.getSubjectDN());
            certNum++;
        }

        // Verify the FIRST certificate in the chain matches the private key
        verifyCertMatchesKey(clientCert, privateKeyAlias, androidKeyStore);

        // Add ALL CA certificates to trust store
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);

        int i = 0;
        for (java.security.cert.Certificate cert : caCerts) {
            X509Certificate x509 = (X509Certificate) cert;
            String alias = "ca-cert-" + i;
            trustStore.setCertificateEntry(alias, x509);
            Log.d(TAG, "  ✓ Added to trust: " + x509.getSubjectDN());
            i++;
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        Log.d(TAG, "✓ TrustManager configured with " + i + " CA cert(s)");

        // WRAP the TrustManager to log what the server presents
        TrustManager[] originalTrustManagers = tmf.getTrustManagers();
        TrustManager[] wrappedTrustManagers = new TrustManager[] {
                new X509TrustManager() {
                    private X509TrustManager delegate = (X509TrustManager) originalTrustManagers[0];

                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType)
                            throws CertificateException {
                        delegate.checkClientTrusted(chain, authType);
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType)
                            throws CertificateException {
                        Log.d(TAG, "========================================");
                        Log.d(TAG, "→ Server presented certificate chain:");
                        Log.d(TAG, "  Chain length: " + chain.length);
                        for (int j = 0; j < chain.length; j++) {
                            Log.d(TAG, "  Server cert[" + j + "]:");
                            Log.d(TAG, "    Subject: " + chain[j].getSubjectDN());
                            Log.d(TAG, "    Issuer: " + chain[j].getIssuerDN());
                            try {
                                chain[j].checkValidity();
                                Log.d(TAG, "    Valid: YES");
                            } catch (Exception e) {
                                Log.e(TAG, "    Valid: NO - " + e.getMessage());
                            }
                        }
                        try {
                            delegate.checkServerTrusted(chain, authType);
                            Log.d(TAG, "✅ Server certificate chain TRUSTED!");
                            Log.d(TAG, "========================================");
                        } catch (CertificateException e) {
                            Log.e(TAG, "❌ Server certificate chain REJECTED!");
                            Log.e(TAG, "   Reason: " + e.getMessage());
                            Log.e(TAG, "========================================");
                            throw e;
                        }
                    }

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return delegate.getAcceptedIssuers();
                    }
                }
        };

        // Use the FULL client certificate chain for the KeyManager
        KeyManager[] keyManagers = new KeyManager[] {
                new AndroidKeystoreKeyManager(privateKeyAlias, androidKeyStore, clientCertArray)
        };
        Log.d(TAG, "✓ KeyManager created with " + clientCertArray.length + " cert(s) in chain");

        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(keyManagers, wrappedTrustManagers, new SecureRandom()); // Use wrappedTrustManagers

        Log.d(TAG, "✅ SSLContext created successfully");
        return sc;
    }

    @ReactMethod
    public void checkKeyExists(String privateKeyAlias, Callback callback) {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            boolean exists = keyStore.containsAlias(privateKeyAlias);
            if (callback != null)
                callback.invoke(exists);
        } catch (Exception e) {
            if (callback != null)
                callback.invoke(false);
        }
    }

    @ReactMethod
    public void listKeyAliases(Callback callback) {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            Enumeration<String> aliases = keyStore.aliases();
            StringBuilder sb = new StringBuilder("Available aliases:\n");
            while (aliases.hasMoreElements()) {
                sb.append("- ").append(aliases.nextElement()).append("\n");
            }
            if (callback != null)
                callback.invoke(sb.toString());
        } catch (Exception e) {
            if (callback != null)
                callback.invoke("Error: " + e.getMessage());
        }
    }
}

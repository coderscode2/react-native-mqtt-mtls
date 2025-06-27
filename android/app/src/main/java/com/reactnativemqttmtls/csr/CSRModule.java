package com.reactnativemqttmtls.csr;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Promise;

import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.StringWriter;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

public class CSRModule extends ReactContextBaseJavaModule {
    private static final String TAG = "CSRModule";
    private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    private static final String ALIAS = "GENERAC_PWRVIEW_ECC_KEY_ALIAS";
    private static final String CLIENT_CERT_ALIAS = "clientCert";
    private static final String ROOT_CA_ALIAS = "rootCa";

    public CSRModule(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    public String getName() {
        return "CSRModule";
    }

    public static KeyPair generateSoftwareECCKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        keyPairGenerator.initialize(ecSpec);
        return keyPairGenerator.generateKeyPair();
    }

    @ReactMethod
    public void generateECCKeyPair(Promise promise) {
        try {
            KeyPair keyPair = generateSoftwareECCKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            // Store the key pair in AndroidKeyStore
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);

            // Create a certificate chain with just the public key (self-signed for storage)
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(publicKey.getEncoded())
            );
            keyStore.setKeyEntry(ALIAS, privateKey, null, new Certificate[]{cert});

            promise.resolve("ECC key pair generated and stored successfully");
        } catch (Exception e) {
            promise.reject("ECC_ERROR", "Failed to generate ECC key pair: " + e.getMessage());
        }
    }

    @ReactMethod
    public void generateCSR(
            String cn,
            String serialNum,
            String userId,
            String country,
            String state,
            String locality,
            String organization,
            String organizationalUnit,
            Promise promise) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(ALIAS, null);
            PublicKey publicKey = keyStore.getCertificate(ALIAS).getPublicKey();

            String csr = createCSR(cn, serialNum, userId, country, state, locality, organization, organizationalUnit, privateKey, publicKey);
            promise.resolve(csr);
        } catch (Exception e) {
            promise.reject("CSR_ERROR", "Failed to generate CSR: " + e.getMessage());
        }
    }

    @ReactMethod
    public void storeCertificateInfo(
        String clientCertIssuingCa,
        String clientCert,
        String clientCertExpiration,
        Promise promise) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null, null);

            // Parse and store client certificate
            String base64ClientCert = clientCert
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            byte[] clientCertBytes = Base64.decode(base64ClientCert, Base64.DEFAULT);
            InputStream clientCertStream = new ByteArrayInputStream(clientCertBytes);
            X509Certificate clientCertificate = (X509Certificate) certFactory.generateCertificate(clientCertStream);
            keyStore.setCertificateEntry(CLIENT_CERT_ALIAS, clientCertificate);

            // Parse and store root CA certificate
            String base64CaCert = clientCertIssuingCa
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
            byte[] caCertBytes = Base64.decode(base64CaCert, Base64.DEFAULT);
            InputStream caCertStream = new ByteArrayInputStream(caCertBytes);
            X509Certificate caCertificate = (X509Certificate) certFactory.generateCertificate(caCertStream);
            keyStore.setCertificateEntry(ROOT_CA_ALIAS, caCertificate);

            promise.resolve(true);
        } catch (Exception e) {
            Log.e(TAG, "Exception: " + e.getMessage());
            promise.reject("CERTIFICATE_STORAGE_ERROR", "Failed to store certificates: " + e.getMessage());
        }
    }

    private String createCSR(
            String cn,
            String serialNum,
            String userId,
            String country,
            String state,
            String locality,
            String organization,
            String organizationalUnit,
            PrivateKey privateKey,
            PublicKey publicKey) throws Exception {
        X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        if (cn != null && !cn.isEmpty()) {
            nameBuilder.addRDN(BCStyle.CN, cn);
        }
        if (serialNum != null && !serialNum.isEmpty()) {
            nameBuilder.addRDN(BCStyle.SERIALNUMBER, serialNum);
        }
        if (country != null && !country.isEmpty()) {
            nameBuilder.addRDN(BCStyle.C, country);
        }
        if (state != null && !state.isEmpty()) {
            nameBuilder.addRDN(BCStyle.ST, state);
        }
        if (locality != null && !locality.isEmpty()) {
            nameBuilder.addRDN(BCStyle.L, locality);
        }
        if (organization != null && !organization.isEmpty()) {
            nameBuilder.addRDN(BCStyle.O, organization);
        }
        if (organizationalUnit != null && !organizationalUnit.isEmpty()) {
            nameBuilder.addRDN(BCStyle.OU, organizationalUnit);
        }

        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        PKCS10CertificationRequestBuilder csrBuilder = new PKCS10CertificationRequestBuilder(
                nameBuilder.build(), subjectPublicKeyInfo);
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withECDSA");
        var csr = csrBuilder.build(signerBuilder.build(privateKey));

        StringWriter stringWriter = new StringWriter();
        try (PemWriter pemWriter = new PemWriter(stringWriter)) {
            pemWriter.writeObject(new PemObject("CERTIFICATE REQUEST", csr.getEncoded()));
        }
        return stringWriter.toString();
    }
}
package com.reactnativemqttmtls.csr;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Promise;

public class CSRModule extends ReactContextBaseJavaModule {
    public CSRModule(ReactApplicationContext context) {
        super(context);
    }

    @Override
    public String getName() {
        return "CSRModule";
    }

    @ReactMethod
    public void generateCSR(String commonName, Promise promise) {
        try {
            // Implementation for CSR generation
            promise.resolve("CSR for " + commonName);
        } catch (Exception e) {
            promise.reject("CSR_ERROR", e.getMessage());
        }
    }
}
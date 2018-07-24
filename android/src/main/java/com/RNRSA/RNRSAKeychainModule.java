
package com.RNRSA;

import android.util.Log;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.WritableNativeMap;

import java.security.KeyPair;

import java.security.NoSuchAlgorithmException;

public class RNRSAKeychainModule extends ReactContextBaseJavaModule {
    private final static String ANDROID_KEYSTORE = "AndroidKeyStore";

    private final ReactApplicationContext reactContext;

    public RNRSAKeychainModule(ReactApplicationContext reactContext) {
        super(reactContext);
        this.reactContext = reactContext;
    }

    @Override
    public String getName() {
        return "RNRSAKeychain";
    }

    @ReactMethod
    public void generateDeterministic(String keyTag, int bits, int eInt, String seed, Promise promise) {
        WritableNativeMap keys = new WritableNativeMap();

        try {
            byte[] bseed = new byte[seed.length()];
            for (int i=0; i<seed.length(); i++) bseed[i] = (byte) seed.charAt(i);

            KeyPair pair = RNRSADeterministicGenerator.generateDeterministic(bits, eInt, bseed);
            EC EC = new EC(keyTag, "BC", pair);
            keys.putString("public", EC.getPublicKey());
            keys.putString("private", EC.getPrivateKey()); // TODO remove -- leaking key to shell is bad
            promise.resolve(keys);
        } catch (Exception e) {
            promise.reject("Error", e.toString() + e.getMessage() + Log.getStackTraceString(e));
        }
    }

    @ReactMethod
    public void generate(String keyTag, Promise promise) {
        WritableNativeMap keys = new WritableNativeMap();

        try {
            EC EC = new EC(keyTag, ANDROID_KEYSTORE);
            keys.putString("public", EC.getPublicKey());
            promise.resolve(keys);
        } catch (NoSuchAlgorithmException e) {

            promise.reject("Error", e.getMessage() + Log.getStackTraceString(e));
        } catch (Exception e) {
            promise.reject("Error", e.getMessage() + Log.getStackTraceString(e));
        }
    }

    @ReactMethod
    public void getPublicKey(String keyTag, Promise promise) {
        try {
            EC EC = new EC(keyTag, ANDROID_KEYSTORE);
            String publicKey = EC.getPublicKey();
            promise.resolve(publicKey);
        } catch (NoSuchAlgorithmException e) {
            promise.reject("Error", e.getMessage() + Log.getStackTraceString(e));
        } catch (Exception e) {
            promise.reject("Error", e.getMessage() + Log.getStackTraceString(e));
        }
    }

    @ReactMethod
    public void deletePrivateKey(String keyTag, Promise promise) {
        try {
            EC EC = new EC(keyTag,ANDROID_KEYSTORE);
            EC.deletePrivateKey();
            promise.resolve(1);
        } catch (NoSuchAlgorithmException e) {
            promise.reject("Error", e.getMessage() + Log.getStackTraceString(e));
        } catch (Exception e) {
            promise.reject("Error", e.getMessage() + Log.getStackTraceString(e));
        }
    }

    @ReactMethod
    public void encrypt(String message, String keyTag, Promise promise) {

        try {
            EC EC = new EC(keyTag,ANDROID_KEYSTORE);
            String encodedMessage = EC.encrypt(message);
            promise.resolve(encodedMessage);
        } catch (Exception e) {
            promise.reject("Error", e.getMessage() + Log.getStackTraceString(e));
        }
    }

    @ReactMethod
    public void encrypt64(String message, String keyTag, Promise promise) {

        try {
            EC EC = new EC(keyTag,ANDROID_KEYSTORE);
            String encodedMessage = EC.encrypt64(message);
            promise.resolve(encodedMessage);
        } catch (Exception e) {
            promise.reject("Error", e.getMessage() + Log.getStackTraceString(e));
        }
    }

    @ReactMethod
    public void decrypt(String encodedMessage, String keyTag, Promise promise) {

        try {
            EC EC = new EC(keyTag,ANDROID_KEYSTORE);
            String message = EC.decrypt(encodedMessage);
            promise.resolve(message);

        } catch (Exception e) {
            promise.reject("Error", e.getMessage() + Log.getStackTraceString(e));
        }
    }

    @ReactMethod
    public void decrypt64(String encodedMessage, String keyTag, Promise promise) {

        try {
            EC EC = new EC(keyTag,ANDROID_KEYSTORE);
            String message = EC.decrypt64(encodedMessage);
            promise.resolve(message);

        } catch (Exception e) {
            promise.reject("Error", e.getMessage() + Log.getStackTraceString(e));
        }
    }

    @ReactMethod
    public void sign(String message, String keyTag, Promise promise) {

        try {
            EC EC = new EC(keyTag,ANDROID_KEYSTORE);
            String signature = EC.sign(message);
            promise.resolve(signature);

        } catch (Exception e) {
            promise.reject("Error", e.getMessage() + Log.getStackTraceString(e));
        }
    }

    @ReactMethod
    public void sign64(String message, String keyTag, Promise promise) {

        try {
            EC EC = new EC(keyTag,ANDROID_KEYSTORE);
            String signature = EC.sign(message);
            promise.resolve(signature);

        } catch (Exception e) {
            promise.reject("Error", e.getMessage() + Log.getStackTraceString(e));
        }
    }

    @ReactMethod
    public void verify(String signature, String message, String keyTag, Promise promise) {

        try {
            EC EC = new EC(keyTag,ANDROID_KEYSTORE);
            boolean verified = EC.verify(signature, message);
            promise.resolve(verified);

        } catch (Exception e) {
            promise.reject("Error", e.getMessage() + Log.getStackTraceString(e));
        }
    }

    @ReactMethod
    public void verify64(String signature, String message, String keyTag, Promise promise) {

        try {
            EC EC = new EC(keyTag,ANDROID_KEYSTORE);
            boolean verified = EC.verify(signature, message);
            promise.resolve(verified);

        } catch (Exception e) {
            promise.reject("Error", e.getMessage() + Log.getStackTraceString(e));
        }
    }

}

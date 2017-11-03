
package com.RNRSA;

import android.util.Log;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.WritableNativeMap;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class RNRSAKeychainModule extends ReactContextBaseJavaModule {

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
  public void generate(String keyTag, Promise promise)  {
    WritableNativeMap keys = new WritableNativeMap();

    try {
        RSA rsa = new RSA();
        rsa.generate(keyTag);
        keys.putString("public",  rsa.getPublicKey());
        promise.resolve(keys);
    } catch(NoSuchAlgorithmException e) {
      promise.reject("Error", e.getMessage());
    } catch(Exception e) {
      promise.reject("Error", e.getMessage());
    }
  }

  @ReactMethod
  public void deletePrivateKey(String keyTag, Promise promise)  {
    try {
        RSA rsa = new RSA(keyTag);
        rsa.deletePrivateKey();
        promise.resolve(1);
    } catch(NoSuchAlgorithmException e) {
      promise.reject("Error", e.getMessage());
    } catch(Exception e) {
      promise.reject("Error", e.getMessage());
    }
  }

  @ReactMethod
  public void encrypt(String message, String keyTag, Promise promise)  {

      try {
          RSA rsa = new RSA(keyTag);
          String encodedMessage = rsa.encrypt(message);
          promise.resolve(encodedMessage);
      } catch(Exception e) {
          promise.reject("Error", e.getMessage());
      }
  }

  @ReactMethod
  public void encrypt64(String message, String keyTag, Promise promise)  {

      try {
          RSA rsa = new RSA(keyTag);
          String encodedMessage = rsa.encrypt64(message);
          promise.resolve(encodedMessage);
      } catch(Exception e) {
          promise.reject("Error", e.getMessage());
      }
  }


  @ReactMethod
  public void decrypt(String encodedMessage, String keyTag, Promise promise)  {

      try {
          RSA rsa = new RSA(keyTag);
          String message = rsa.decrypt(encodedMessage);
          promise.resolve(message);

      } catch(Exception e) {
          promise.reject("Error", e.getMessage());
      }
  }

  @ReactMethod
  public void decrypt64(String encodedMessage, String keyTag, Promise promise)  {

      try {
          RSA rsa = new RSA(keyTag);
          String message = rsa.decrypt64(encodedMessage);
          promise.resolve(message);

      } catch(Exception e) {
          promise.reject("Error", e.getMessage());
      }
  }

    @ReactMethod
    public void sign(String message, String keyTag, Promise promise)  {

        try {
            RSA rsa = new RSA(keyTag);
            String signature = rsa.sign(message);
            promise.resolve(signature);

        } catch(Exception e) {
            promise.reject("Error", e.getMessage());
        }
    }

    @ReactMethod
    public void sign64(String message, String keyTag, Promise promise)  {

        try {
            RSA rsa = new RSA(keyTag);
            String signature = rsa.sign64(message);
            promise.resolve(signature);

        } catch(Exception e) {
            promise.reject("Error", e.getMessage());
        }
    }

    @ReactMethod
    public void verify(String signature, String message, String keyTag, Promise promise)  {

        try {
            RSA rsa = new RSA(keyTag);
            boolean verified = rsa.verify(signature, message);
            promise.resolve(verified);

        } catch(Exception e) {
            promise.reject("Error", e.getMessage());
        }
    }

    @ReactMethod
    public void verify64(String signature, String message, String keyTag, Promise promise)  {

        try {
            RSA rsa = new RSA(keyTag);
            boolean verified = rsa.verify64(signature, message);
            promise.resolve(verified);

        } catch(Exception e) {
            promise.reject("Error", e.getMessage());
        }
    }



}

package com.RNRSA;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.WritableNativeMap;
import com.facebook.react.bridge.Promise;

import java.security.NoSuchAlgorithmException;

public class RNRSAModule extends ReactContextBaseJavaModule {

  private final ReactApplicationContext reactContext;

  public RNRSAModule(ReactApplicationContext reactContext) {
    super(reactContext);
    this.reactContext = reactContext;
  }

  @Override
  public String getName() {
    return "RNRSA";
  }

  @ReactMethod
  public void generate(Promise promise)  {
    WritableNativeMap keys = new WritableNativeMap();

    try {
        EC EC = new EC();
        EC.generate();
        keys.putString("public",  EC.getPublicKey());
        keys.putString("private",  EC.getPrivateKey());
        promise.resolve(keys);
    } catch(NoSuchAlgorithmException e) {
      promise.reject("Error", e.getMessage());
    } catch(Exception e) {
      promise.reject("Error", e.getMessage());
    }
  }

  @ReactMethod
  public void encrypt(String message, String publicKeyString, Promise promise)  {

      try {
          EC EC = new EC();
          EC.setPublicKey(publicKeyString);
          String encodedMessage = EC.encrypt(message);
          promise.resolve(encodedMessage);
      } catch(Exception e) {
          promise.reject("Error", e.getMessage());
      }
  }

  @ReactMethod
  public void encrypt64(String message, String publicKeyString, Promise promise)  {

      try {
          EC EC = new EC();
          EC.setPublicKey(publicKeyString);
          String encodedMessage = EC.encrypt64(message);
          promise.resolve(encodedMessage);
      } catch(Exception e) {
          promise.reject("Error", e.getMessage());
      }
  }


  @ReactMethod
  public void decrypt(String encodedMessage, String privateKeyString, Promise promise)  {

      try {
          EC EC = new EC();
          EC.setPrivateKey(privateKeyString);
          String message = EC.decrypt(encodedMessage);
          promise.resolve(message);

      } catch(Exception e) {
          promise.reject("Error", e.getMessage());
      }
  }

  @ReactMethod
  public void decrypt64(String encodedMessage, String privateKeyString, Promise promise)  {

      try {
          EC EC = new EC();
          EC.setPrivateKey(privateKeyString);
          String message = EC.decrypt64(encodedMessage);
          promise.resolve(message);

      } catch(Exception e) {
          promise.reject("Error", e.getMessage());
      }
  }

    @ReactMethod
    public void sign(String message, String privateKeyString, Promise promise)  {

        try {
            EC EC = new EC();
            EC.setPrivateKey(privateKeyString);
            String signature = EC.sign(message);
            promise.resolve(signature);

        } catch(Exception e) {
            promise.reject("Error", e.getMessage());
        }
    }
    @ReactMethod
    public void verify(String signature, String message, String publicKeyString, Promise promise)  {

        try {
            EC EC = new EC();
            EC.setPublicKey(publicKeyString);
            boolean verified = EC.verify(signature, message);
            promise.resolve(verified);

        } catch(Exception e) {
            promise.reject("Error", e.getMessage());
        }
    }



}
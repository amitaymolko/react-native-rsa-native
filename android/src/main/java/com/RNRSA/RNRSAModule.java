
package com.RNRSA;

import android.os.AsyncTask;

import com.facebook.react.bridge.NoSuchKeyException;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.WritableNativeMap;
import com.facebook.react.bridge.Promise;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class RNRSAModule extends ReactContextBaseJavaModule {

  private static final String SHA256withRSA = "SHA256withRSA";
  private static final String SHA512withRSA = "SHA512withRSA";

  private final ReactApplicationContext reactContext;

  public RNRSAModule(ReactApplicationContext reactContext) {
    super(reactContext);
    this.reactContext = reactContext;
  }

  @Override
  public String getName() {
    return "RNRSA";
  }

  @Override
  public Map<String, Object> getConstants() {
    final Map<String, Object> constants = new HashMap<>();
    constants.put(SHA256withRSA, SHA256withRSA);
    constants.put(SHA512withRSA, SHA512withRSA);
    return constants;
  }

  @ReactMethod
  public void generate(final Promise promise) {
    this.generateKeys(2048, promise);
  }
  
  @ReactMethod
  public void generateKeys(final int keySize, final Promise promise) {
    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        WritableNativeMap keys = new WritableNativeMap();

        try {
          KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA);
          kpg.initialize(2048);
          KeyPair kp = kpg.generateKeyPair();
          String publicKey = "-----BEGIN PUBLIC KEY-----" + Base64.encodeToString(kp.getPublic().getEncoded(), Base64.DEFAULT) + "-----END PUBLIC KEY-----";
          String privateKey = "-----BEGIN RSA PRIVATE KEY-----" + Base64.encodeToString(kp.getPrivate().getEncoded(), Base64.DEFAULT) + "-----END RSA PRIVATE KEY-----";

          keys.putString("public", publicKey);
          keys.putString("private", privateKey);
          promise.resolve(keys);
        } catch (NoSuchAlgorithmException e) {
          promise.reject("Error", e.getMessage());
        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }

  @ReactMethod
  public void encrypt(final String message, final String publicKeyString, final Promise promise) {
    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        try {
          RSA rsa = new RSA();
          rsa.setPublicKey(publicKeyString);
          String encodedMessage = rsa.encrypt(message);
          promise.resolve(encodedMessage);
        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }

  @ReactMethod
  public void encrypt64(final String message, final String publicKeyString, final Promise promise) {
    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        try {
          RSA rsa = new RSA();
          rsa.setPublicKey(publicKeyString);
          String encodedMessage = rsa.encrypt64(message);
          promise.resolve(encodedMessage);
        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }

  @ReactMethod
  public void decrypt(final String encodedMessage, final String privateKeyString, final Promise promise) {
    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        try {
          RSA rsa = new RSA();
          rsa.setPrivateKey(privateKeyString);
          String message = rsa.decrypt(encodedMessage);
          promise.resolve(message);

        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }

  @ReactMethod
  public void decrypt64(final String encodedMessage, final String privateKeyString, final Promise promise) {
    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        try {
          RSA rsa = new RSA();
          rsa.setPrivateKey(privateKeyString);
          String message = rsa.decrypt64(encodedMessage);
          promise.resolve(message);

        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }

  @ReactMethod
  public void sign(final String message, final String privateKeyString, final Promise promise) {
    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        try {
          RSA rsa = new RSA();
          rsa.setPrivateKey(privateKeyString);
          String signature = rsa.sign(message, SHA512withRSA);
          promise.resolve(signature);

        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }

  @ReactMethod
  public void signWithAlgorithm(final String message, final String privateKeyString, final String algorithm, final Promise promise) {
    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        try {
          RSA rsa = new RSA();
          rsa.setPrivateKey(privateKeyString);
          String signature = rsa.sign(message, algorithm);
          promise.resolve(signature);

        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }

  @ReactMethod
  public void sign64(final String message, final String privateKeyString, final Promise promise) {
    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        try {
          RSA rsa = new RSA();
          rsa.setPrivateKey(privateKeyString);
          String signature = rsa.sign64(message, SHA512withRSA);
          promise.resolve(signature);

        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }

  @ReactMethod
  public void sign64WithAlgorithm(final String message, final String privateKeyString, final String algorithm, final Promise promise) {
    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        try {
          RSA rsa = new RSA();
          rsa.setPrivateKey(privateKeyString);
          String signature = rsa.sign64(message, algorithm);
          promise.resolve(signature);

        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }

  @ReactMethod
  public void verify(final String signature, final String message, final String publicKeyString,
      final Promise promise) {
    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        try {
          RSA rsa = new RSA();
          rsa.setPublicKey(publicKeyString);
          boolean verified = rsa.verify(signature, message, SHA512withRSA);
          promise.resolve(verified);

        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }

  @ReactMethod
  public void verifyWithAlgorithm(final String signature, final String message, final String publicKeyString, final String algorithm,
      final Promise promise) {
    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        try {
          RSA rsa = new RSA();
          rsa.setPublicKey(publicKeyString);
          boolean verified = rsa.verify(signature, message, algorithm);
          promise.resolve(verified);

        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }

  @ReactMethod
  public void verify64(final String signature, final String message, final String publicKeyString,
      final Promise promise) {
    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        try {
          RSA rsa = new RSA();
          rsa.setPublicKey(publicKeyString);
          boolean verified = rsa.verify64(signature, message, SHA512withRSA);
          promise.resolve(verified);

        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }

  @ReactMethod
  public void verify64WithAlgorithm(final String signature, final String message, final String publicKeyString, final String algorithm,
      final Promise promise) {
    AsyncTask.execute(new Runnable() {
      @Override
      public void run() {
        try {
          RSA rsa = new RSA();
          rsa.setPublicKey(publicKeyString);
          boolean verified = rsa.verify64(signature, message, algorithm);
          promise.resolve(verified);

        } catch (Exception e) {
          promise.reject("Error", e.getMessage());
        }
      }
    });
  }
}

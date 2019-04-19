# react-native-rsa-native

A native implementation of RSA key generation and encryption/decryption, sign/verify.
Keychain implementation
Implementation is in PKCS1

## Support

iOS 10+
android 4.1+ (API 16)

## Status

Features:
Generation,
Encryption,
Decryption,
Sign,
Verify,
Keychain support

## Getting started

`$ yarn add react-native-rsa-native`

or:

`$ npm install react-native-rsa-native --save`

### Mostly automatic installation:

`$ react-native link react-native-rsa-native`

## iOS

In your React Native Xcode project, right click on your project and go 'Add Files to ...', then navigate to <your-project-root>/node_modules/react-native-rsa-native/ios and select the RNRSA.xcodeproj file. Then in the build settings for your target under 'Link Binary With Libraries', add libRNRSA.a.

## Documentation
### RSA Class

A class that performs RSA cryptographic primitives
in a simple and straightforward manner.
If you would prefer to use the underlying operating system's built-in
security keychain, use [the RSAKeychain Class](#rsakeychain-class) instead.

#### generateKeys
`static generateKeys(keySize : number) : Promise<KeyPair>`

Generate a public/private key pair of the given key size.

#### generate
`static generate() : Promise<KeyPair>`

Equivalent to `generateKeys(2048)`

#### encrypt
`static encrypt(message : string, publicKey : string) : Promise<string>`

Encrypt a given message with the provided public key, so it is decryptable with the matching private key.

#### decrypt
`static decrypt(encodedMessage : string, privateKey : string) : Promise<string>`

Decrypt a given encrypted message using the private key.

#### sign
`static sign(message: string, privateKey : string) : Promise<string>`
Sign a given message with the private key, so that any user with the message, the returned signature, and the matching public key can verify it was signed under this key.

#### verify
`static verify(signature : string, message : string, publicKey : string) : Promise<boolean>`

Verify whether or not a provided signature was produced by signing the given message with the private key paired to the provided public key.

### RSAKeychain Class

Like [the RSA Class](#rsa-class),
but when its methods are called, instead of directly accessing the private key,
the private key is stored in the underlying operating system's keychain
(see documentation
[for iOS](https://developer.apple.com/documentation/security/keychain_services) and
[for Android](https://developer.android.com/reference/android/security/KeyChain))
using a tag which the app can use to access it.
Methods then take this tag instead of the private key.

### KeyPair Type

Note: The `KeyPair` type does not strictly exist.
Documentation provided here for convenience of understanding the return types
of other methods.

Property | Description
--|--
`private : string` | The RSA private key.
`public : string` | The RSA public key.

## Usage

```

import {RSA, RSAKeychain} from 'react-native-rsa-native';

RSA.generateKeys(4096) // set key size
  .then(keys => {
    console.log('4096 private:', keys.private) // the private key
    console.log('4096 public:', keys.public) // the public key
  })

RSA.generate()
  .then(keys => {
    console.log(keys.private) // the private key
    console.log(keys.public) // the public key
    RSA.encrypt('1234', keys.public)
      .then(encodedMessage => {
        RSA.decrypt(encodedMessage, keys.private)
          .then(message => {
            console.log(message);
          })
        })

    RSA.sign(secret, keys.private)
      .then(signature => {
        console.log(signature);

        RSA.verify(signature, secret, keys.public)
          .then(valid => {
            console.log(valid);
          })
        })
  })

// Example utilizing the keychain for private key secure storage

let keyTag = 'com.domain.mykey';
let secret = "secret message";

RSAKeychain.generate(keyTag)
  .then(keys => {
    console.log(keys.public);
    console.log(secret);

    return RSAKeychain.encrypt(secret, keyTag)
      .then(encodedMessage => {
        console.log(encodedMessage);

        RSAKeychain.decrypt(encodedMessage, keyTag)
          .then(message => {
            console.log(message);
          })
        })
  })
  .then(() => {
  return RSAKeychain.sign(secret, keyTag)
    .then(signature => {
      console.log('signature', signature);

      RSAKeychain.verify(signature, secret, keyTag)
        .then(valid => {
          console.log('verified', valid);
        })
      })
  })
  .then(() => {
    RSAKeychain.deletePrivateKey(keyTag)
    .then( success => {
      console.log('delete success', success)
    })
  });
```
Check out example App.js for a full example


## Credit

* Originally based on https://github.com/SamSaffron/react-native-key-pair
* iOS implementation [reference](https://developer.apple.com/library/content/documentation/Security/Conceptual/CertKeyTrustProgGuide/KeyRead.html#//apple_ref/doc/uid/TP40001358-CH222-SW1)


## Donate

ETH: 0xDc2F8D78098749EB3ECdF79Fe32Efda86fEEFc3c

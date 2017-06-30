# react-native-rsa-native

A native implementation of RSA key generation and encryption/decryption.
Implementation is in PKCS1

## Status

Android: Generation, Encryption, Decryption
iOS: Generation, Encryption, Decryption

*Need to check cross platform encrypt/decrypt

## Getting started

`$ yarn add react-native-rsa-native`

or:

`$ npm install react-native-rsa-native --save`

### Mostly automatic installation:

`$ react-native link react-native-rsa-native`

## iOS

In your React Native Xcode project, right click on your project and go 'Add Files to ...', then navigate to <your-project-root>/node_modules/react-native-rsa-native/ios and select the RNRSA.xcodeproj file. Then in the build settings for your target under 'Link Binary With Libraries', add libRNRSA.a.

## Usage

```

import RSA, {RNRSAKeychain} from 'react-native-rsa-native';

RSA.generate()
  .then(keys => {
    console.log(keys.private) // the private key
    console.log(keys.public) // the public key
    RNRSA.encrypt('1234', keys.public)
      .then(encodedMessage => {
        RNRSA.decrypt(encodedMessage, keys.private)
          .then(message => {
            console.log(message)
          })
        })
    })

// Example utilizing the keychain for private key secure storage

let keyTag = 'com.domain.mykey';
let secret = "secret message";

RNRSAKeychain.generate(keyTag)
  .then(keys => {
    console.log(keys.public);

    console.log(secret);

    RSA.encrypt(secret, keyTag)
      .then(encodedMessage => {
        console.log(encodedMessage);

        RSA.decrypt(encodedMessage, keyTag)
          .then(message => {
            console.log(message);
          })
        })
    });
```


## Credit

* Originally based on https://github.com/SamSaffron/react-native-key-pair
* iOS implementation [reference](https://developer.apple.com/library/content/documentation/Security/Conceptual/CertKeyTrustProgGuide/KeyRead.html#//apple_ref/doc/uid/TP40001358-CH222-SW1)

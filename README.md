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


## Usage

```
RSA.generate()
  .then(keys => {
    console.log(keys.private) // encoded private key
    console.log(keys.public) // encoded public key
    RSA.encrypt('secret message', keys.public)
      .then(encodedMessage => {
        RSA.decrypt(encodedMessage, keys.private)
          .then(message => {
            console.log(message)
          })
      })
  })
```

## Credit

Originally based on https://github.com/SamSaffron/react-native-key-pair
iOS implementation reference https://developer.apple.com/library/content/documentation/Security/Conceptual/CertKeyTrustProgGuide/KeyRead.html#//apple_ref/doc/uid/TP40001358-CH222-SW1

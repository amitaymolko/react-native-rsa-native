
# react-native-rsa-native

A native implementation of RSA key generation and encryption/decryption.   
Implementation is in PKCS1  

## Status

Android: Generation, Encryption, Decryption  
iOS: Generation, Encryption, Decryption  

*Need to check cross platform encrypt/decrypt

## Usage

```
RSA.generate()
  .then(keys => {
    console.log(keys.private) // the private key
    console.log(keys.public) // the public key
    RSA.encrypt('1234', keys.public)
      .then(encodedMessage => {
        RSA.decrypt(encodedMessage, keys.private)
          .then(message => {
            console.log(message)
          })
      })
  })
```

## Getting started

`$ yarn add react-native-rsa-native` 

or if you are old: 

`$ npm install react-native-rsa-native --save`

### Mostly automatic installation:

`$ react-native link react-native-rsa-native`


#### iOS
*Needs [Cocoapods](https://cocoapods.org/)*

add this to your `Podfile`:

```
pod 'react-native-rsa-native', path: '../node_modules/react-native-rsa-native'
```

## Credit

Originally based on https://github.com/SamSaffron/react-native-key-pair
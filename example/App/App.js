import React, { Component } from 'react'
import { View, Text } from 'react-native'

import {RSA, RSAKeychain} from 'react-native-rsa-native';

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
        console.log('signature', signature);

        RSA.verify(signature, secret, keys.public)
          .then(valid => {
            console.log('verified', valid);
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

    RSAKeychain.encrypt(secret, keyTag)
      .then(encodedMessage => {
        console.log(encodedMessage);

        RSAKeychain.decrypt(encodedMessage, keyTag)
          .then(message => {
            console.log(message);
          })
        })

    RSAKeychain.sign(secret, keyTag)
      .then(signature => {
        console.log('signature', signature);

        RSAKeychain.verify(signature, secret, keyTag)
          .then(valid => {
            console.log('verified', valid);
          })
        })
  });

class App extends Component {
  componentWillMount () {
  
  }

  componentWillUnmount () {
    
  }

  render () {
    return (
      <View>
        <Text>
            Demo
        </Text>
      </View>
    )
  }
}

export default App

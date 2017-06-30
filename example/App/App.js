import React, { Component } from 'react'
import { View, Text } from 'react-native'

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

import React, { Component } from 'react'
import { View, Text } from 'react-native'

import {RSA, RSAKeychain} from 'react-native-rsa-native';

// RSA.generate()
//   .then(keys => {
//     console.log(keys.private) // the private key
//     console.log(keys.public) // the public key
//     RSA.encrypt('1234', keys.public)
//       .then(encodedMessage => {
//         RSA.decrypt(encodedMessage, keys.private)
//           .then(message => {
//             console.log(message);
//           })
//         })

//     RSA.sign(secret, keys.private)
//       .then(signature => {
//         console.log('signature', signature);

//         RSA.verify(signature, secret, keys.public)
//           .then(valid => {
//             console.log('verified', valid);
//           })
//         })
//   })

// const pkcs1PublicKey = `-----BEGIN PUBLIC KEY-----
// MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx9Van+tCkoPDTs/U8KAl
// k5LDUZ7f643MPz50lKT1CJbhosefAFrI7CP+joy61ROCx2JYeRo6BrA98oanPm5m
// 0fcqLDV8gpT/LYSbsafU9e7t8mkTd052QimI8UmZGbhcg5L2cbOE9PSNFSqGR+vN
// FFgRYYMBu4uN3HCSrW8N6ObqlQCz57EGrpRbfAdqLKjXxtXOhL4UxV06geUUFzjf
// QU0Iko6xshRJvCV4+SIF9MRPTXnUsMWcNCsRKGQXx6dMQEsh/PV6cXIoIdVuPqZg
// CWXOeyTIZI/Hmpv+7OkaBtDREa3rvDFXOE17pjXRXd1QIUQfcpytlP8scLIFrO8M
// 2wIDAQAB
// -----END PUBLIC KEY-----`;

// RSA.encrypt('1234', pkcs1PublicKey)
//   .then(encryptedMessage => {
//     console.log('pkcs1PublicKey', encryptedMessage)
//   })
//   .catch(err => {
//     console.log('err', err)
//   })

// Example utilizing the keychain for private key secure storage

let keyTag = 'com.domain.mykey';
let secret = 'secret message';

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

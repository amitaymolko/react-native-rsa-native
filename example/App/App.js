import React, { Component } from 'react'
import { View, Text } from 'react-native'

import {RSA, RSAKeychain} from 'react-native-rsa-native';

let secret = 'secret message';
let keyTag = 'com.domain.mykey';

RSA.generate()
  .then(keys => {
    console.log('private:', keys.private) // the private key
    console.log('public:', keys.public) // the public key
    RSA.encrypt('1234', keys.public)
      .then(encodedMessage => {
        console.log('encoded message:', encodedMessage)
        RSA.decrypt(encodedMessage, keys.private)
          .then(message => {
            console.log('decoded message:', message);
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

  const iosPkcs1PrivateKey = `-----BEGIN RSA PRIVATE KEY-----
  MIIEpAIBAAKCAQEA9nH5sqTOfSns7op8NHD2nHuXt/j1rodcbb7MXVSeK+0jx6np
  o2Oidc6J1fxSi5xBpIhEo6eGQD+b0SQFQMe6k33kqfRk4vzNi5n4lzFWWoyVgHKi
  CYrk+JdSGX2BK0t52ca8ZASBs099jIjiL8Hk4PPdpjrUk0sHaXDDFzhmHy8XRbH1
  21Pz148UytAnABxSO1F5gkGKvf23WyL0mb9kgfR9yX9wuCLtei8COT8Vz9l15nsc
  yPFCvC/mul6HTA7ukAXbtTS1wgRmorM2XTtnwpbMEpAwM48UhH7qcMFJVVagmpTI
  w0uFTXfYybJt8NysO1KslM7Yqswg5Aq36gxugwIDAQABAoIBABglu88uydLGyGHp
  LNlgljFoBMoweTY0KjDQqKqeb28jacWXFv789L6xUZ0nf5kRYvcxqPQWJpfmA6j+
  7ArYZyYriDvE6Bu7pJJAsHR0D5+Itd9jnA/uTZg0D4XS39SzrQlTKUNtk53TtJwQ
  D4WZbIlEK9wtWIXkLKI+u8brLkpwvBBcXrXUqBnqngJEBFKvr+utlzvnN6Ra9Kjw
  cpDCRkGvQyXav1rFwEe2pkaOnQ/r+y7lJqoT/+XyOjcTdkh2PhN7w9dHpGEmI6mL
  iQjbqEEXnAbyI1Cf753J1joLb5/+fVJ1DQiO8nMcpK+vzCRm5HNHgOG4KKjmQMRX
  NEGqoGkCgYEA/EJFi94JWgJaZ3r02EfG4TuIYQE0KIR/vn3iCdw6uGIclsgTwiuE
  z8OB1LWNvHzpiFfohESxrykflCjyATzExpqr2BpNlxyt0vp5RidggGKaiwjmbf1P
  89uTYGWwI8LxCBTbU+s9cjDInx84aKUjzTFb4i1dwwcLntaNKceORnsCgYEA+hmh
  rBlsF1QNCH2FsQqoI6oSsSbMJBw/FTF8fyIvvLC8Yas25Ax73nerw1Kpc2AC9bbn
  XlzfwmEgYdMdu+biZzJpsD5LaplbkUw1IZvTKlHwIUg/C/QjfaN11YOx+sxgo8lh
  2eFTGjnNjSwU943RmBckQGD7WEsc/Z0mJRzbPZkCgYEA+yh0m/y3LOH45tzaGNjm
  H+ypLYQITWsW0S/+tTiLUneE5W9RlNrFgiKzCni1JPzte22jOMY4byCvq1FVGnxJ
  oz/uZtxRcmoAe3Yc9wdPoqQKIPH8k3hJeY+eXbUBOannV9eERDqMVDxUE3H/NNlv
  GubRCBGJMBu8qyoNJJLmii8CgYEAtKo7XcTnjlqLJ6z1HJUkLM84vXvXT+aPs1GS
  K4yYi2foTW2PM2HJQUWVcH2QJuYefT1pGYNhqFrdN414FzqMJhwGuOfnNtQdj3JL
  l0GnYxTZsFEuKgZsdN/VyS1fLlrhHK/m3aulinZjBC3p34I0+/cLmu3z4y4vfQ0+
  duTHg1ECgYB98Z0eCi/ct+m+B3YhCEdcXUzvIZY0sEJUlqIiGyxkLuVEdIPIFUqj
  f1+VVZQA0d6BwruDSptq8x5aR3rdAlb5A71NYWQGOIPa2E5SIFZmzrZjyeeCfyB8
  eMOrE2W6flCRaTDOH4kFuw4JqrymBLcgP/OTYO0T9MCOKeqP0wbyNg==
  -----END RSA PRIVATE KEY-----`

  const iosEncodedMessage = `xW7YdqRZPxMjUydRuY/bWO78Jvz/GM9qx+0soQEsheqfs+5nLugkBXiJC9J6if3j
  oCH/uBLYC41X6tlpX/L/u+ujaYQTIRcnL1f74ZFcX8Ox1vTp47Ie5XteRcLbuAmk
  vOzQ41q/ddUe8co67ShuiTmwI3Q4bUNukHEkwcpbD20JllKRR3wfYCoej05O29Xj
  9QuO0gKjEis5le6dWrMuVQVT70rBZQkAoBAesSjEYw0LKKjyylpUHmNy7y1XNbb2
  LA8kC70ZvNWYL+cIU2ZKts9HYtTbIAonL91uP6Bf+M0uUkqc2zxEL9EpFmwGx3Q0
  JQUqPQPB+wHb7DlDFJdQ6A==`

  RSA.decrypt(iosEncodedMessage, iosPkcs1PrivateKey)
  .then(message => {
    console.log('ios decoded message:', message);
  })

  const androidPkcs1PrivateKey = `-----BEGIN RSA PRIVATE KEY-----
  MIIEpAIBAAKCAQEAx+Wc5/pZQFLxisjb5TbkVKzm1y/q/JbVZ4kq9D8isFI6GimQ
  yF7y8gdmq4YPblCfnUIlFFbdWsbUX8dW6nLEmWQhqHheLOybHfrv/YaSUZzlmUav
  qNYAv5xm3/F7rAeFjZN5fVpATdLl3AlhxBckxwZe2Z0AdEuOdUGDbdBwGoWrfCLv
  r3wWSZfJ0we+DfK76WGDFdK/5jSm9yQePTmY1Hc/QkaULadFtZn/O5xl3uyS768i
  MEo+Zt6/6863ej6WJekvZ3XKUr/Sqvw+b8nzEyH7RCnFvDgXK7LMe+Tc6HdNaTeV
  w3nE2pQqqTx8LCNhj4HsobQi3ndgYuOJM0O0wQIDAQABAoIBAQDAPCd9y3rjaiCR
  eAJIV1aTu8cvMAzKpn9J11awlrrUV+86U7jBiNYYPVfWIdFbJDurbv3bpoGvF8EK
  7te+FWrNnMbljgP7LfsqhLUg2baCt+DxW1H4iv0jR9SDDmcBlCYydZ2DGDT44pVc
  2sTjX+JlZ9H1cpAKRtMUHlG3XJlCVo+JnaslzWIfk0Itzd55ntTm4bXEgZ9j3+79
  eyoHgnY3LWTrIYDlHwS9ypYdLEbyCf89MP+VFDADjs1CTr31WzuVkKKUXvxATgfq
  CZhxHgZgHgvAvWRGQnqwIo6uMBBCD1DsAxj9MG7AI0+1F6wiMGyBEQ1agxZST2W4
  wb6UVpsxAoGBAPUZJ1zjPGiCxCNdaOWB3oPyL/6o9azQsyR4GEoGUjDdCDU9zKys
  WQn63f83jN9dZvNH68Dc3sb0k5Ip1TSqqdIKJA8Ms1GAEsHSMQAM6euGn6D4PdqU
  JPqwqIcQkaPIY/zEkfuh7J8U9p7WpicHz/WNfqsY2kFBzdpjNO6AmWGNAoGBANDJ
  xItF+Rd9x8lWrD6xf/U2vTLai4EZF1piLo5Tu7BwqHg8BlXpn4dBvefMxuDSELJ+
  WfNwgwyrNaCM0Rs7hlnF+V6kuFr4lJJgORp578NhvncLGfrxQrVlTt1pablh+iTD
  8IT2o9NEzgiRxjq3Qxo+iVprX0tfoz1UwqLYgEEFAoGBAM3HC5xaEEqyl1gVwc8H
  BToEaTVGx9UK94zD46iqu/DYcl64/xFuNedCH4Z6LiUOdzQECzRGfCfQCeHqi12H
  d8KnzvRvtlHT1Gu0PH2NWgvrYDQ2lz/fp1huX1/eklhPE1uR8fqxTUeWwyRClQcp
  8Ph5joK5/+xQAjO7nSItCBm1AoGAFblYtPET6OjSd9WH2IIZgUcvynHI4CbfMi1T
  EMYPml0uekwskJXdXnJtswewjcXtrNTOwTCswg2yZ8EfJMk9wmuB9eIHuJdyxgQz
  DNkxJFAwRCyoiF7ABSXEXe9Q69QQ9fBZP0x2YU4gbe3VBVj6J2noWrsfUDVkQ8Zk
  9hK2zY0CgYBiMwbP0nafeaB+YO9v2mvwHeCAnFtBsVZkUVp75alsAujr/YEKSKEQ
  YiFzbWLAkY7gBrS2b8tbHKXkkYfcWWlpM85ir/uqyNy/6Rb7CPkKUkCInIwZ9Vi2
  clP6STevOnNTlyYhNgesy50tSPJEWO6ysC/petudc5t1e1FEM/pBkg==
  -----END RSA PRIVATE KEY-----`

  const androidEncodedMessage = `Z3iPkJiJCrXLaT11RtwBuSJa4rGbJ7JfDSHMNn/UaLUnGIzFmMT6ZRMtaSmWJhw3pXBES1IqufJB
  Wk5vdZuDD7o5AP8i5GHrgVGbf6ix6DIH1+PiJzcfwBcSdEuCMEsustk+tBirK/HuxYt0HQV3B8Sw
  EFAFOAPh3y2CsSC7Ibn5Q5cWeDYxfs8XANezs0H3i/X+KZP8owIrKnsERErc0E6bJ/V3tGCoFb+5
  m0SibGo5B446iH57hTHf3Sv6GYcThk5+BqP/08VVQ2YXy+oMPng2nVnvzGONdJzfq+9GAKWMx6CE
  yiSiGz7AYGDb04FmekL8KqEKy6nTlVERlbwWRg==`

  RSA.decrypt(androidEncodedMessage, androidPkcs1PrivateKey)
  .then(message => {
    console.log('android decoded message:', message);
  })
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
    return RSAKeychain.getPublicKey(keyTag)
    .then(publicKey => {
      console.log('getPublicKey', publicKey)
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

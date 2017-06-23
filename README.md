
# react-native-rsa-native

A native implementation of Public/Private RSA key generation and encryption/decryption.

## Usage

```
import RSA from 'react-native-rsa-native'
RSA.generate((keys) => {
  console.log(keys.private) // the private key
  console.log(keys.public) // the public key
})
```

## Getting started

`$ yarn add react-native-rsa-native` 

or if you are old: 

`$ npm install react-native-rsa-native --save`

### Mostly automatic installation

`$ react-native link react-native-rsa-native`

### Manual installation


#### iOS

1. In XCode, in the project navigator, right click `Libraries` ➜ `Add Files to [your project's name]`
2. Go to `node_modules` ➜ `react-native-rsa-native` and add `RNRSA.xcodeproj`
3. In XCode, in the project navigator, select your project. Add `libRNRSA.a` to your project's `Build Phases` ➜ `Link Binary With Libraries`
4. Run your project (`Cmd+R`)<

#### Android

1. Open up `android/app/src/main/java/[...]/MainActivity.java`
  - Add `import com.reactlibrary.RNRSAPackage;` to the imports at the top of the file
  - Add `new RNRSAPackage()` to the list returned by the `getPackages()` method
2. Append the following lines to `android/settings.gradle`:
  	```
  	include ':react-native-rsa-native'
  	project(':react-native-rsa-native').projectDir = new File(rootProject.projectDir, 	'../node_modules/react-native-rsa-native/android')
  	```
3. Insert the following lines inside the dependencies block in `android/app/build.gradle`:
  	```
      compile project(':react-native-rsa-native')
  	```

## Credit

Based on https://github.com/SamSaffron/react-native-key-pair
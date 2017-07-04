
import { NativeModules } from 'react-native';

const { RNRSAKeychain } = NativeModules;
const { RNRSA } = NativeModules;

export { RNRSAKeychain as RSAKeychain, RNRSA as RSA };

export default RNRSA;


import { NativeModules } from 'react-native';

const { RNRSAKeychain } = NativeModules;
const { RNRSA } = NativeModules;

export { RNRSAKeychain, RNRSAKeychain as RSAKeychain, RNRSA, RNRSA as RSA };

export default RNRSA;

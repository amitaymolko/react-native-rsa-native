
import { NativeModules } from 'react-native';

const { RNRSAKeychain, RNRSA } = NativeModules;

export { RNRSAKeychain, RNRSAKeychain as RSAKeychain, RNRSA, RNRSA as RSA };

export default RNRSA;

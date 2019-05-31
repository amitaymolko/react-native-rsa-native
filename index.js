
import { NativeModules } from 'react-native';

const { RNRSAKeychain } = NativeModules;
const { RNRSA } = NativeModules;
RNRSAKeychain.Digest_SHA256=RNRSAKeychain['SHA-256'];
RNRSAKeychain.Digest_SHA512=RNRSAKeychain['SHA-512'];
export { RNRSAKeychain, RNRSAKeychain as RSAKeychain, RNRSA, RNRSA as RSA };

export default RNRSA;

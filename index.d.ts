declare module 'react-native-rsa-native' {
	interface PublicKey {
		public: string;
	}

	interface CSRKey {
		csr: string;
	}

	interface KeyPair extends PublicKey {
		private: string;
	}

	type TypeCrypto  = 
		'SHA256withRSA'|
		'SHA512withRSA'|
		'SHA1withRSA'|
		'SHA256withECDSA'|
		'SHA512withECDSA'|
		'SHA1withECDSA'
	

	namespace RSA {
		export function generate(): Promise<PublicKey>;
		export function generateKeys(keySize: number): Promise<KeyPair>;
		export function encrypt(data: string, key: string): Promise<string>;
		export function decrypt(data: string, key: string): Promise<string>;
		export function encrypt64(data: string, key: string): Promise<string>;
		export function decrypt64(data: string, key: string): Promise<string>;
		export function sign(data: string, key: string): Promise<string>;
		export function signHash(hash:string,key):Promise<string>:
		export function signWithAlgorithm(data: string, key: string, signature?: TypeCrypto): Promise<string>;
		export function sign64(data: string, key: string): Promise<string>;
		export function sign64WithAlgorithm(data: string, key: string, signature?: TypeCrypto): Promise<string>;
		export function verify(data: string, secretToVerify: string, key: string): Promise<boolean>;
		export function verifyWithAlgorithm(data: string, secretToVerify: string, key: string, signature?: TypeCrypto): Promise<boolean>;
		export function verify64(data: string, secretToVerify: string, key: string): Promise<boolean>;
		export function verify64WithAlgorithm(data: string, secretToVerify: string, key: string, signature?: TypeCrypto): Promise<boolean>;
		export const SHA256withRSA: string;
		export const SHA512withRSA: string;
		export const SHA1withRSA: string;
		export const SHA256withECDSA: string;
		export const SHA512withECDSA: string;
		export const SHA1withECDSA: string;
	}

	namespace RSAKeychain {
		export function generate(keyTag: string): Promise<PublicKey>;
		export function generateEC(keyTag: string): Promise<PublicKey>;
		export function generateCSR(keyTag: string, CN: string, signature?: TypeCrypto): Promise<CSRKey>;
		export function generateKeys(keyTag: string, keySize: number): Promise<PublicKey>;
		export function generateCSRWithEC(cn: String,keyTag: string, keySize: number): Promise<PublicKey & CSRKey>;
		export function deletePrivateKey(keyTag: string): Promise<boolean>;
		export function encrypt(data: string, keyTag: string): Promise<string>;
		export function decrypt(data: string, keyTag: string): Promise<string>;
		export function encrypt64(data: string, keyTag: string): Promise<string>;
		export function decrypt64(data: string, keyTag: string): Promise<string>;
		export function sign(data: string, keyTag: string): Promise<string>;
		export function signWithAlgorithm(data: string, keyTag: string, signature?: TypeCrypto): Promise<string>;
		export function sign64WithAlgorithm(data: string, keyTag: string, signature?: TypeCrypto): Promise<string>;
		export function verify(data: string, secretToVerify: string, keyTag: string): Promise<boolean>;
		export function verifyWithAlgorithm(data: string, secretToVerify: string, keyTag: string, signature?: TypeCrypto): Promise<boolean>;
		export function verify64WithAlgorithm(data: string, secretToVerify: string, keyTag: string, signature?: TypeCrypto): Promise<boolean>;
		export function getPublicKey(keyTag: string): Promise<string | undefined>;
		export function getPublicKeyDER(keyTag: string): Promise<string | undefined>;
		export function getPublicKeyRSA(keyTag: string): Promise<string | undefined>;
		export function deletePrivateKey(keyTag: string): Promise<boolean>;
		export const SHA256withRSA: string;
		export const SHA512withRSA: string;
		export const SHA1withRSA: string;
		export const SHA256withECDSA: string;
		export const SHA512withECDSA: string;
		export const SHA1withECDSA: string;
	}

	export { RSA, RSAKeychain, KeyPair, CSRKey };
}

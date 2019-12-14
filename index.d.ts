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

	namespace RSA {
		export function generate(keySize: number): Promise<PublicKey>;
		export function generateKeys(keySize: number): Promise<KeyPair>;
		export function encrypt(data: string, key: string): Promise<string>;
		export function decrypt(data: string, key: string): Promise<string>;
		export function sign(data: string, key: string): Promise<string>;
		export function signWithAlgorithm(data: string, key: string, signature?: 'SHA256withRSA' | 'SHA512withRSA'): Promise<string>;
		export function verify(data: string, secretToVerify: string, key: string): Promise<boolean>;
		export const SHA256withRSA: string;
		export const SHA512withRSA: string;
	}

	namespace RSAKeychain {
		export function generate(keyTag: string, keySize: number): Promise<PublicKey>;
		export function generateKeys(keyTag: string, keySize: number): Promise<PublicKey>;
		export function generateCSRWithEC(cn: String,keyTag: string, keySize: number): Promise<PublicKey & CSRKey>;
		export function deletePrivateKey(keyTag: string): Promise<boolean>;
		export function encrypt(data: string, keyTag: string): Promise<string>;
		export function decrypt(data: string, keyTag: string): Promise<string>;
		export function sign(data: string, keyTag: string): Promise<string>;
		export function signWithAlgorithm(data: string, keyTag: string, signature?: 'SHA256withRSA' | 'SHA512withRSA' | 'SHA1withRSA'): Promise<string>;
		export function verify(data: string, secretToVerify: string, keyTag: string): Promise<boolean>;
		export function verifyWithAlgorithm(data: string, secretToVerify: string, keyTag: string, signature?: 'SHA256withRSA' | 'SHA512withRSA' | 'SHA1withRSA'): Promise<boolean>;
		export function getPublicKey(keyTag: string): Promise<string | undefined>;
		export const SHA256withRSA: string;
		export const SHA512withRSA: string;
	}

	export { RSA, RSAKeychain };
}

declare module 'react-native-rsa-native' {
	interface PublicKey {
		public: string;
	}

	interface KeyPair extends PublicKey {
		private: string;
	}

	namespace RSA {
		export function generateKeys(keySize: number): Promise<KeyPair>;
		export function encrypt(data: string, key: string): Promise<string>;
		export function decrypt(data: string, key: string): Promise<string>;
		export function sign(data: string, key: string): Promise<string>;
		export function verify(data: string, secretToVerify: string, key: string): Promise<boolean>;
	}

	namespace RSAKeychain {
		export function generateKeys(keyTag: string, keySize: number): Promise<PublicKey>;
		export function deletePrivateKey(keyTag: string): Promise<boolean>;
		export function encrypt(data: string, keyTag: string): Promise<string>;
		export function decrypt(data: string, keyTag: string): Promise<string>;
		export function sign(data: string, keyTag: string): Promise<string>;
		export function sign(data: string, keyTag: string, signature?: 'SHA256WithRSA' | 'SHA512WithRSA'): Promise<string>;
		export function verify(data: string, secretToVerify: string, keyTag: string): Promise<boolean>;
		export function getPublicKey(keyTag: string): Promise<string | undefined>;
		export const SHA256WITHRSA: string;
		export const SHA512WITHRSA: string;
	}

	export { RSA, RSAKeychain };
}

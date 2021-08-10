

//
//  RSANative.swift
//  BVLinearGradient

import Foundation
import CommonCrypto

typealias SecKeyPerformBlock = (SecKey) -> ()


class RSAECNative: NSObject {
    
    var publicKey: SecKey?
    var privateKey: SecKey?
    var keyTag: String?
    let publicKeyTag: String?
    let privateKeyTag: String?
    var publicKeyBits: Data?
    var keyAlgorithm = KeyAlgorithm.rsa(signatureType: .sha512)
    
    public init(keyTag: String?){
        self.publicKeyTag = "\(keyTag ?? "").public"
        self.privateKeyTag = "\(keyTag ?? "").private"
        self.keyTag = keyTag
        super.init()
    }
    
    public convenience override init(){
        self.init(keyTag: nil)
    }
    
    public func generate(keySize: Int) -> Bool? {
        var publicKeyParameters: [String: AnyObject] = [
            String(kSecAttrAccessible): kSecAttrAccessibleAlways,
        ]
        
        var privateKeyParameters: [String: AnyObject] = [
            String(kSecAttrAccessible): kSecAttrAccessibleAlways,
        ]
        
        if((self.keyTag) != nil){
            privateKeyParameters[String(kSecAttrIsPermanent)] = kCFBooleanTrue
            privateKeyParameters[String(kSecAttrApplicationTag)] = self.privateKeyTag as AnyObject
            
            publicKeyParameters[String(kSecAttrIsPermanent)] = kCFBooleanTrue
            publicKeyParameters[String(kSecAttrApplicationTag)] = self.publicKeyTag as AnyObject
            
        }
        
        #if !arch(i386) && !arch(x86_64)
        //This only works for Secure Enclave consistign of 256 bit key, note, the signatureType is irrelavent for this check
        if keyAlgorithm.type == KeyAlgorithm.ec(signatureType: .sha1).type{
            let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                         kSecAttrAccessibleAlwaysThisDeviceOnly,
                                                         .privateKeyUsage,
                                                         nil)!   // Ignore error
            
            privateKeyParameters[String(kSecAttrAccessControl)] = access
        }
        #endif
        
        //Define what type of keys to be generated here
        var parameters: [String: AnyObject] = [
            String(kSecReturnRef): kCFBooleanTrue,
            kSecPublicKeyAttrs as String: publicKeyParameters as AnyObject,
            kSecPrivateKeyAttrs as String: privateKeyParameters as AnyObject,
        ]
        parameters[String(kSecAttrKeySizeInBits)] = keySize as AnyObject
        if #available(iOS 10, *) {
            parameters[String(kSecAttrKeyType)] = keyAlgorithm.secKeyAttrType
        } else {
            // Fallback on earlier versions
            parameters[String(kSecAttrKeyType)] = keyAlgorithm.secKeyAttrTypeiOS9
        }
        
        #if !arch(i386) && !arch(x86_64)
        
        //iOS only allows EC 256 keys to be secured in enclave. This will attempt to allow any EC key in the enclave, assuming iOS will do it outside of the enclave if it doesn't like the key size, note: the signatureType is irrelavent for this check
        if keyAlgorithm.type == KeyAlgorithm.ec(signatureType: .sha1).type{
            parameters[String(kSecAttrTokenID)] = kSecAttrTokenIDSecureEnclave
        }
        
        #endif
        
        // TODO: Fix for when not set keytag and dont use keychain
        if #available(iOS 10.0, *) {
            
            var error: Unmanaged<CFError>?
            self.privateKey = SecKeyCreateRandomKey(parameters as CFDictionary, &error)
            
            if self.privateKey == nil {
                print("Error occured: keys weren't created")
                return nil
            }
            
            self.publicKey = SecKeyCopyPublicKey(self.privateKey!)
            
        } else {
            // Fallback on earlier versions
            
            let result = SecKeyGeneratePair(parameters as CFDictionary, &publicKey, &privateKey)
            
            if result != errSecSuccess{
                print("Error occured: \(result)")
                return nil
            }
        }
        
        guard self.publicKey != nil else {
            print( "Error  in setUp(). PublicKey shouldn't be nil")
            return nil
        }
        
        guard self.privateKey != nil else{
            print("Error  in setUp(). PrivateKey shouldn't be nil")
            return nil
        }
        return true
    }
    
    public func generateEC() -> Bool? {
        self.keyAlgorithm = KeyAlgorithm.ec(signatureType: .sha256)
        // ios support 256
        return self.generate(keySize: 256);
    }
    
    public func generateCSR(CN: String?, withAlgorithm: String) -> String? {
        self.setAlgorithm(algorithm: withAlgorithm)
        //        self.privateKey = self.getPrivateKeyChain(tag: self.privateKeyTag!)
        self.publicKeyBits = self.getPublicKeyChainData(tag: self.publicKeyTag!)
        var csrString: String?
        let csrBlock: SecKeyPerformBlock = { privateKey in
            let csr = CertificateSigningRequest(commonName: CN, organizationName: nil, organizationUnitName: nil, countryName: nil, stateOrProvinceName: nil, localityName: nil, keyAlgorithm: self.keyAlgorithm)
            csrString = csr.buildCSRAndReturnString(self.publicKeyBits!, privateKey: privateKey)
        }
        
        if ((self.keyTag) != nil) {
            self.performWithPrivateKeyTag(keyTag: self.privateKeyTag!, block: csrBlock)
        } else {
            csrBlock(self.privateKey!);
        }
        return csrString
    }
    
    private func getPublicKeyChainData(tag : String) -> Data? {
        //Ask keychain to provide the publicKey in bits
        var query: [String: AnyObject] = [
            String(kSecClass): kSecClassKey,
            String(kSecAttrApplicationTag): self.publicKeyTag as AnyObject,
            String(kSecReturnData): kCFBooleanTrue
        ]
        
        if #available(iOS 10, *) {
            query[String(kSecAttrKeyType)] = self.keyAlgorithm.secKeyAttrType
        } else {
            // Fallback on earlier versions
            query[String(kSecAttrKeyType)] = self.keyAlgorithm.secKeyAttrTypeiOS9
        }
        
        var tempPublicKeyBits:AnyObject?
        
        let result = SecItemCopyMatching(query as CFDictionary, &tempPublicKeyBits)
        
        switch result {
        case errSecSuccess:
            guard let keyBits = tempPublicKeyBits as? Data else {
                print("error in: convert to publicKeyBits")
                return nil
            }
            return keyBits
            
        default:
            print("error in: convert to publicKeyBits")
            return nil
        }
    }
    
    private func setAlgorithm(algorithm: String) -> Void {
        switch algorithm {
        case "SHA256withRSA":
            self.keyAlgorithm = .rsa(signatureType: .sha256)
        case "SHA512withRSA":
            self.keyAlgorithm = .rsa(signatureType: .sha512)
        case "SHA1withRSA":
            self.keyAlgorithm = .rsa(signatureType: .sha1)
        case "SHA256withECDSA":
            self.keyAlgorithm = .ec(signatureType: .sha256)
        case "SHA512withECDSA":
            self.keyAlgorithm = .ec(signatureType: .sha512)
        case "SHA1withECDSA":
            self.keyAlgorithm = .ec(signatureType: .sha1)
        default:
            self.keyAlgorithm = .rsa(signatureType: .sha1)
        }
    }
    
    
    public func deletePrivateKey(){
        var query: [String: AnyObject] = [
            String(kSecClass)             : kSecClassKey,
            String(kSecAttrApplicationTag): self.privateKeyTag as AnyObject,
            String(kSecReturnRef)         : true as AnyObject
        ]
        
        if #available(iOS 10, *) {
            query[String(kSecAttrKeyType)] = self.keyAlgorithm.secKeyAttrType
        } else {
            // Fallback on earlier versions
            query[String(kSecAttrKeyType)] = self.keyAlgorithm.secKeyAttrTypeiOS9
        }
        let result = SecItemDelete(query as CFDictionary)
        
        if result != errSecSuccess{
            print("Error delete private key: \(result)")
            //            return nil
        }
    }
    
    public func encodedPublicKeyRSA() -> String? {
        if ((self.keyTag) != nil) {
            var encodedPublicKey: String?
            self.performWithPublicKeyTag(tag: self.publicKeyTag!) { (publicKey) in
                encodedPublicKey = self.externalRepresentationForPublicKeyRSA(key: publicKey)
            }
            return encodedPublicKey;
        }
        if(self.publicKey == nil) { return nil }
        return self.externalRepresentationForPublicKeyRSA(key: self.publicKey!)
    }
    
    public func encodedPublicKeyDER() -> String? {
        
        if ((self.keyTag) != nil) {
            var encodedPublicKey: String?
            self.performWithPublicKeyTag(tag: self.publicKeyTag!) { (publicKey) in
                encodedPublicKey = self.externalRepresentationForPublicKeyDER(key: publicKey)
            }
            return encodedPublicKey;
        }
        if(self.publicKey == nil) { return nil }
        return self.externalRepresentationForPublicKeyDER(key: self.publicKey!)
    }
    
    public func encodedPublicKey() -> String? {
        
        if ((self.keyTag) != nil) {
            var encodedPublicKey: String?
            self.performWithPublicKeyTag(tag: self.publicKeyTag!) { (publicKey) in
                encodedPublicKey = self.externalRepresentationForPublicKey(key: publicKey)
            }
            return encodedPublicKey;
        }
        if(self.publicKey == nil) { return nil }
        return self.externalRepresentationForPublicKey(key: self.publicKey!)
    }
    
    public func encodedPrivateKeyRSA() -> String? {
        if ((self.keyTag) != nil) {
            var encodedPrivateKey: String?
            self.performWithPrivateKeyTag(keyTag: self.privateKeyTag!) { (privateKey) in
                encodedPrivateKey = self.externalRepresentationForPrivateKeyRSA(key: privateKey)
            }
            return encodedPrivateKey;
        }
        if(self.privateKey == nil) { return nil }
        return self.externalRepresentationForPrivateKeyRSA(key: self.privateKey!)
    }
    
    public func encodedPrivateKeyDER() -> String? {
        if ((self.keyTag) != nil) {
            var encodedPrivateKey: String?
            self.performWithPrivateKeyTag(keyTag: self.privateKeyTag!) { (privateKey) in
                encodedPrivateKey = self.externalRepresentationForPrivateKeyDER(key: privateKey)
            }
            return encodedPrivateKey;
        }
        if(self.privateKey == nil) { return nil }
        return self.externalRepresentationForPrivateKeyDER(key: self.privateKey!)
    }
    
    
    public func setPublicKey(publicKey: String) -> Bool? {
        guard let publicKeyStr = RSAECFormatter.stripHeaders(pemString: publicKey) else { return false }
        let query: [String: AnyObject] = [
            String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
            String(kSecAttrKeyClass): kSecAttrKeyClassPublic,
        ]
        print(publicKeyStr, "publicKeyStrpublicKeyStr")
        var error: Unmanaged<CFError>?
        guard let data = Data(base64Encoded: publicKeyStr, options: .ignoreUnknownCharacters) else { return false }
        print(data, "datadatadata")
        if #available(iOS 10.0, *) {
            guard let key = SecKeyCreateWithData(data as CFData, query as CFDictionary, &error) else { return false }
            self.publicKey = key
            return true
        } else {
            // Fallback on earlier versions
        }
        return false
    }
    
    public func setPrivateKey(privateKey: String) -> Bool? {
        guard let privateKeyStr = RSAECFormatter.stripHeaders(pemString: privateKey) else { return nil }
        let query: [String: AnyObject] = [
            String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
            String(kSecAttrKeyClass): kSecAttrKeyClassPrivate,
        ]
        var error: Unmanaged<CFError>?
        guard let data = Data(base64Encoded: privateKeyStr, options: .ignoreUnknownCharacters) else { return nil }
        if #available(iOS 10.0, *) {
            guard let key = SecKeyCreateWithData(data as CFData, query as CFDictionary, &error) else { return nil }
            self.privateKey = key
            return true
        } else {
            // Fallback on earlier versions
        }
        return nil
    }
    
    public func encrypt64(message: String) -> String? {
        guard let data =  Data(base64Encoded: message, options: .ignoreUnknownCharacters) else { return nil }
        let encrypted = self._encrypt(data: data)
        return encrypted?.base64EncodedString(options: NSData.Base64EncodingOptions(rawValue: 0))
    }
    
    
    public func encrypt(message: String) -> String? {
        guard let data =  message.data(using: .utf8) else { return nil }
        let encrypted = self._encrypt(data: data)
        return encrypted?.base64EncodedString(options: .lineLength64Characters)
    }
    
    public func _encrypt(data: Data) -> Data? {
        var cipherText: Data?
        
        // Closures
        let encryptor:SecKeyPerformBlock = { publicKey in
            if #available(iOS 10.0, *) {
                let canEncrypt = SecKeyIsAlgorithmSupported(publicKey, .encrypt, .rsaEncryptionPKCS1)
                if(canEncrypt){
                    var error: Unmanaged<CFError>?
                    cipherText = SecKeyCreateEncryptedData(publicKey, .rsaEncryptionPKCS1, data as CFData, &error) as Data?
                }
            } else {
                // Fallback on earlier versions
            };
        }
        
        
        if ((self.keyTag) != nil) {
            self.performWithPublicKeyTag(tag: self.publicKeyTag!, block: encryptor)
        } else {
            encryptor(self.publicKey!);
        }
        return cipherText;
    }
    
    public func decrypt64(message: String) -> String? {
        guard let data =  Data(base64Encoded: message, options: .ignoreUnknownCharacters) else { return nil }
        let decrypted = self._decrypt(data: data)
        return decrypted?.base64EncodedString(options: NSData.Base64EncodingOptions(rawValue: 0))
    }
    
    
    public func decrypt(message: String) -> String? {
        guard let data =  Data(base64Encoded: message, options: .ignoreUnknownCharacters) else { return nil }
        let decrypted = self._decrypt(data: data)
        return String(data: decrypted!, encoding: String.Encoding.utf8)
    }
    
    private func _decrypt(data: Data) -> Data? {
        var clearText: Data?
        let decryptor: SecKeyPerformBlock = {privateKey in
            if #available(iOS 10.0, *) {
                let canEncrypt = SecKeyIsAlgorithmSupported(privateKey, .decrypt, .rsaEncryptionPKCS1)
                if(canEncrypt){
                    var error: Unmanaged<CFError>?
                    clearText = SecKeyCreateDecryptedData(privateKey, .rsaEncryptionPKCS1, data as CFData, &error) as Data?
                }
                
            } else {
                // Fallback on earlier versions
            };
        }
        
        if ((self.keyTag) != nil) {
            self.performWithPrivateKeyTag(keyTag: self.privateKeyTag!, block: decryptor)
        } else {
            decryptor(self.privateKey!);
        }
        return clearText
    }
    
    public func sign64(b64message: String, withAlgorithm: String) -> String? {
        guard let data = Data(base64Encoded: b64message, options: .ignoreUnknownCharacters) else { return nil }
        let encodedSignature = self._sign(messageBytes: data, withAlgorithm: withAlgorithm, withEncodeOption: .lineLength64Characters)
        return encodedSignature
    }
    
    public func sign(message: String, withAlgorithm: String, withEncodeOption: NSData.Base64EncodingOptions) -> String? {
        guard let data =  message.data(using: .utf8) else { return nil }
        let encodedSignature = self._sign(messageBytes: data, withAlgorithm: withAlgorithm, withEncodeOption: withEncodeOption)
        return encodedSignature
    }
    
    private func _sign(messageBytes: Data, withAlgorithm: String, withEncodeOption: NSData.Base64EncodingOptions) -> String? {
        self.setAlgorithm(algorithm: withAlgorithm)
        var encodedSignature: String?
        let signer: SecKeyPerformBlock = { privateKey in
            if #available(iOS 11, *) {
                // Build signature - step 1: SHA1 hash
                // Build signature - step 2: Sign hash
                //            var signature: Data? = nil
                var error: Unmanaged<CFError>?
                
                let signature = SecKeyCreateSignature(privateKey, self.keyAlgorithm.signatureAlgorithm, messageBytes as CFData, &error) as Data?
                
                if error != nil{
                    print("Error in creating signature: \(error!.takeRetainedValue())")
                }
                
                encodedSignature = signature!.base64EncodedString(options: withEncodeOption)
                
            } else {
                // TODO: fix and test
                // Fallback on earlier versions
                
                // Build signature - step 1: SHA1 hash
                var signature = [UInt8](repeating: 0, count: self.keyAlgorithm.availableKeySizes.last!)
                var signatureLen:Int = signature.count
                var messageDataBytes = [UInt8](repeating: 0, count: messageBytes.count)
                messageBytes.copyBytes(to: &messageDataBytes, count: messageBytes.count)
                var digest = [UInt8](repeating: 0, count: self.keyAlgorithm.digestLength)
                let padding = self.keyAlgorithm.padding
                
                switch self.keyAlgorithm {
                    
                case .rsa(signatureType: .sha1), .ec(signatureType: .sha1):
                    
                    var SHA1 = CC_SHA1_CTX()
                    CC_SHA1_Init(&SHA1)
                    CC_SHA1_Update(&SHA1, messageDataBytes, CC_LONG(messageBytes.count))
                    
                    CC_SHA1_Final(&digest, &SHA1)
                    
                case .rsa(signatureType: .sha256), .ec(signatureType: .sha256):
                    
                    var SHA256 = CC_SHA256_CTX()
                    CC_SHA256_Init(&SHA256)
                    CC_SHA256_Update(&SHA256, messageDataBytes, CC_LONG(messageBytes.count))
                    CC_SHA256_Final(&digest, &SHA256)
                    
                case .rsa(signatureType: .sha512), .ec(signatureType: .sha512):
                    
                    var SHA512 = CC_SHA512_CTX()
                    CC_SHA512_Init(&SHA512)
                    CC_SHA512_Update(&SHA512, messageDataBytes, CC_LONG(messageBytes.count))
                    CC_SHA512_Final(&digest, &SHA512)
                    
                }
                
                // Build signature - step 2: Sign hash
                let result = SecKeyRawSign(privateKey, padding, digest, digest.count, &signature, &signatureLen)
                
                if result != errSecSuccess{
                    print("Error signing: \(result)")
                    return
                }
                var signData = Data()
                let zero:UInt8 = 0
                signData.append(zero)
                signData.append(signature, count: signatureLen)
                encodedSignature = signData.base64EncodedString(options: withEncodeOption)
            }
        }
        
        if ((self.keyTag) != nil) {
            self.performWithPrivateKeyTag(keyTag: self.privateKeyTag!, block: signer)
        } else {
            signer(self.privateKey!);
        }
        
        return encodedSignature
    }
    
    public func verify64(encodedSignature: String, withMessage: String, withAlgorithm: String) -> Bool? {
        guard let messageBytes =  Data(base64Encoded: encodedSignature, options: .ignoreUnknownCharacters) else { return nil }
        guard let signatureBytes = Data(base64Encoded: withMessage, options: .ignoreUnknownCharacters) else { return nil }
        return self._verify(signatureBytes: signatureBytes, withMessage: messageBytes, withAlgorithm: withAlgorithm)
    }
    
    public func verify(encodedSignature: String, withMessage: String, withAlgorithm: String) -> Bool? {
        guard let messageBytes =  withMessage.data(using: .utf8) else { return nil }
        guard let signatureBytes = Data(base64Encoded: encodedSignature, options: .ignoreUnknownCharacters) else { return nil }
        return self._verify(signatureBytes:signatureBytes , withMessage: messageBytes, withAlgorithm: withAlgorithm)
    }
    
    private func _verify(signatureBytes: Data, withMessage: Data, withAlgorithm: String) -> Bool? {
        var result = false
        self.setAlgorithm(algorithm: withAlgorithm)
        // Closures
        let verifier: SecKeyPerformBlock = { publicKey in
            if #available(iOS 10.0, *) {
                var error: Unmanaged<CFError>?
                result = SecKeyVerifySignature(publicKey, self.keyAlgorithm.signatureAlgorithm, withMessage as CFData, signatureBytes as CFData, &error)
            } else {
                // Fallback on earlier versions
            }
        }
        
        
        if ((self.keyTag) != nil) {
            self.performWithPublicKeyTag(tag: self.publicKeyTag!, block: verifier)
        } else {
            verifier(self.publicKey!);
        }
        return result
    }
    
    private func performWithPrivateKeyTag(keyTag: String, block: SecKeyPerformBlock){
        var query: [String: AnyObject] = [
            String(kSecClass)             : kSecClassKey,
            String(kSecAttrApplicationTag): keyTag as AnyObject,
            String(kSecReturnRef)         : true as AnyObject
        ]
        
        if #available(iOS 10, *) {
            query[String(kSecAttrKeyType)] = self.keyAlgorithm.secKeyAttrType
        } else {
            // Fallback on earlier versions
            query[String(kSecAttrKeyType)] = self.keyAlgorithm.secKeyAttrTypeiOS9
        }
        
        var result : AnyObject?
        
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        if status == errSecSuccess {
            print("\(keyTag) Key existed!")
            block((result as! SecKey?)!)
        }
    }
    
    private func performWithPublicKeyTag(tag: String, block: SecKeyPerformBlock){
        self.performWithPrivateKeyTag(keyTag: self.privateKeyTag!) { (privateKey) in
            if #available(iOS 10.0, *) {
                let publicKey = SecKeyCopyPublicKey(privateKey)
                block(publicKey!)
            } else {
                // Fallback on earlier versions
            }
        }
        
    }
    
    
    private func externalRepresentationForPublicKeyRSA(key: SecKey) -> String? {
        guard let data = self.dataForKey(key: key) else { return nil }
        return RSAECFormatter.PEMFormattedPublicKeyRSA(publicKeyData: data)
    }
    
    private func externalRepresentationForPublicKey(key: SecKey) -> String? {
        guard let data = self.dataForKey(key: key) else { return nil }
        return RSAECFormatter.PEMFormattedPublicKey(publicKeyData: data)
    }
    
    private func externalRepresentationForPublicKeyDER(key: SecKey) -> String? {
        guard let data = self.dataForKey(key: key) else { return nil }
        let convertedData = RSAKeyEncoding().convertToX509EncodedKey(data)
        return RSAECFormatter.PEMFormattedPublicKey(publicKeyData: convertedData)
    }
    
    private func externalRepresentationForPrivateKeyRSA(key: SecKey) -> String? {
        guard let data = self.dataForKey(key: key) else { return nil }
        return RSAECFormatter.PEMFormattedPrivateKeyRSA(privateKeyData: data)
    }
    
    private func externalRepresentationForPrivateKeyDER(key: SecKey) -> String? {
        guard let data = self.dataForKey(key: key) else { return nil }
        let convertedData = RSAKeyEncoding().convertToX509EncodedKey(data)
        return RSAECFormatter.PEMFormattedPrivateKey(privateKeyData: convertedData)
    }
    
    private func externalRepresentationForPrivateKey(key: SecKey) -> String? {
        guard let data = self.dataForKey(key: key) else { return nil }
        return RSAECFormatter.PEMFormattedPrivateKey(privateKeyData: data)
    }
    
    private func dataForKey(key: SecKey) -> Data? {
        var error: Unmanaged<CFError>?
        var keyData: Data?
        if #available(iOS 10.0, *) {
            keyData = SecKeyCopyExternalRepresentation(key, &error) as Data?
        } else {
            // Fallback on earlier versions
        }
        
        if (keyData == nil) {
            print("error in dataForKey")
            return nil
        }
        
        return keyData;
    }
    
}


#import "RSANative.h"
#import "RSAFormatter.h"

// Code largely based on practices as defined by:
// https://developer.apple.com/library/content/documentation/Security/Conceptual/CertKeyTrustProgGuide/KeyRead.html#//apple_ref/doc/uid/TP40001358-CH222-SW1

typedef void (^SecKeyPerformBlock)(SecKeyRef key);

@interface RSANative ()
@property (nonatomic) NSString *keyTag;
@property (nonatomic) SecKeyRef publicKeyRef;
@property (nonatomic) SecKeyRef privateKeyRef;
@end

@implementation RSANative

- (instancetype)initWithKeyTag:(NSString *)keyTag {
    self = [super init];
    if (self) {
        _keyTag = keyTag;
    }
    return self;
}

- (void)generate:(int)keySize {
    NSMutableDictionary *privateKeyAttributes = [NSMutableDictionary dictionary];

    if (self.keyTag) {
        NSData *tag = [self.keyTag dataUsingEncoding:NSUTF8StringEncoding];

        privateKeyAttributes[(id)kSecAttrIsPermanent] = @YES; // store in keychain
        privateKeyAttributes[(id)kSecAttrApplicationTag] = tag;
    }

	NSMutableDictionary *attributes = [[NSMutableDictionary alloc] init]; 
    [attributes setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [attributes setObject:[NSNumber numberWithInt:keySize] forKey:(__bridge id)kSecAttrKeySizeInBits];
	[attributes setObject:privateKeyAttributes forKey:(__bridge id)kSecPrivateKeyAttrs]; 

    CFErrorRef error = NULL;
    SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes, &error);

    if (!privateKey) {
        NSError *err = CFBridgingRelease(error);
        NSLog(@"%@", err);
    }

    if (!self.keyTag) { // no keychain being used, store reference to keys for later use
        _privateKeyRef = privateKey;
        _publicKeyRef = SecKeyCopyPublicKey(privateKey);
    }
}

- (void)deletePrivateKey {
    if (self.keyTag) {
        NSDictionary *getquery = @{ (id)kSecClass: (id)kSecClassKey,
                                    (id)kSecAttrApplicationTag: self.keyTag,
                                    (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
                                    };
        SecItemDelete((CFDictionaryRef)getquery);
    } else {
        self.privateKey = nil;
    }
}

- (NSString *)encodedPublicKey {
    if (self.keyTag) {
        __block NSString *encodedPublicKey = nil;

        [self performWithPublicKeyTag:self.keyTag block:^(SecKeyRef publicKey) {
            encodedPublicKey = [self externalRepresentationForPublicKey:publicKey];
        }];

        return encodedPublicKey;
    }

    return [self externalRepresentationForPublicKey:self.publicKeyRef];
}

- (NSString *)encodedPrivateKey {
    if (self.keyTag) {
        __block NSString *encodedPrivateKey = nil;

        [self performWithPrivateKeyTag:self.keyTag block:^(SecKeyRef privateKey) {
            encodedPrivateKey = [self externalRepresentationForPrivateKey:privateKey];
        }];

        return encodedPrivateKey;
    }

    return [self externalRepresentationForPrivateKey:self.privateKeyRef];
}

- (NSString *)encodedASN1PublicKey {
    if (self.keyTag) {
        __block NSString *encodedPublicKey = nil;
        
        [self performWithPublicKeyTag:self.keyTag block:^(SecKeyRef publicKey) {
            encodedPublicKey = [self externalASN1Representation:publicKey];
        }];
        
        return encodedPublicKey;
    }
    
    return [self externalASN1Representation:self.publicKeyRef];
}


- (void)setPublicKey:(NSString *)publicKey {
    publicKey = [RSAFormatter stripHeaders: publicKey];
    NSDictionary* options = @{(id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
                              (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPublic,
//                              (id)kSecAttrKeySizeInBits: @2048,
                              };
    CFErrorRef error = NULL;
    NSData *data = [[NSData alloc] initWithBase64EncodedString:publicKey options:NSDataBase64DecodingIgnoreUnknownCharacters];
    SecKeyRef key = SecKeyCreateWithData((__bridge CFDataRef)data,
                                         (__bridge CFDictionaryRef)options,
                                         &error);
    if (!key) {
        NSError *err = CFBridgingRelease(error);
        NSLog(@"%@", err);
    } else {
        _publicKeyRef = key;
    }
}

- (void)setPrivateKey:(NSString *)privateKey {
    privateKey = [RSAFormatter stripHeaders: privateKey];

    NSDictionary* options = @{(id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
                              (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPrivate,
//                              (id)kSecAttrKeySizeInBits: @2048,
                              };
    CFErrorRef error = NULL;
    NSData *data = [[NSData alloc] initWithBase64EncodedString:privateKey options:NSDataBase64DecodingIgnoreUnknownCharacters];
    SecKeyRef key = SecKeyCreateWithData((__bridge CFDataRef)data,
                                         (__bridge CFDictionaryRef)options,
                                         &error);
    if (!key) {
        NSError *err = CFBridgingRelease(error);
        NSLog(@"%@", err);
    } else {
        _privateKeyRef = key;
    }
}

- (NSString *)encrypt64:(NSString*)message {
    NSData *data = [[NSData alloc] initWithBase64EncodedString:message options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSData *encrypted = [self _encrypt: data];
    return [encrypted base64EncodedStringWithOptions:0];
}

- (NSString *)encrypt:(NSString *)message {
    NSData *data = [message dataUsingEncoding:NSUTF8StringEncoding];
    NSData *encrypted = [self _encrypt: data];
    return [encrypted base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
}

- (NSData *)_encrypt:(NSData *)data {
    __block NSData *cipherText = nil;

    void(^encryptor)(SecKeyRef) = ^(SecKeyRef publicKey) {
        BOOL canEncrypt = SecKeyIsAlgorithmSupported(publicKey,
                                                     kSecKeyOperationTypeEncrypt,
                                                     kSecKeyAlgorithmRSAEncryptionPKCS1);
        if (canEncrypt) {
            CFErrorRef error = NULL;
            cipherText = (NSData *)CFBridgingRelease(SecKeyCreateEncryptedData(publicKey,
                                                                               kSecKeyAlgorithmRSAEncryptionPKCS1,
                                                                               (__bridge CFDataRef)data,
                                                                               &error));
            if (!cipherText) {
                NSError *err = CFBridgingRelease(error);
                NSLog(@"%@", err);
            }
        }
    };

    if (self.keyTag) {
        [self performWithPublicKeyTag:self.keyTag block:encryptor];
    } else {
        encryptor(self.publicKeyRef);
    }

    return cipherText;
}

- (NSString *)decrypt64:(NSString*)message {
    NSData *data = [[NSData alloc] initWithBase64EncodedString:message options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSData *decrypted = [self _decrypt: data];
    return [decrypted base64EncodedStringWithOptions:0];
}

- (NSString *)decrypt:(NSString *)message {
    NSData *data = [[NSData alloc] initWithBase64EncodedString:message options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSData *decrypted = [self _decrypt: data];
    return [[NSString alloc] initWithData:decrypted encoding:NSUTF8StringEncoding];
}

- (NSData *)_decrypt:(NSData *)data {
    __block NSData *clearText = nil;

    void(^decryptor)(SecKeyRef) = ^(SecKeyRef privateKey) {

        BOOL canDecrypt = SecKeyIsAlgorithmSupported(privateKey,
                                                     kSecKeyOperationTypeDecrypt,
                                                     kSecKeyAlgorithmRSAEncryptionPKCS1);
        if (canDecrypt) {
            CFErrorRef error = NULL;
            clearText = (NSData *)CFBridgingRelease(SecKeyCreateDecryptedData(privateKey,
                                                                              kSecKeyAlgorithmRSAEncryptionPKCS1,
                                                                              (__bridge CFDataRef)data,
                                                                              &error));
            if (!clearText) {
                NSError *err = CFBridgingRelease(error);
                NSLog(@"%@", err);
            }
        }
    };

    if (self.keyTag) {
        [self performWithPrivateKeyTag:self.keyTag block:decryptor];
    } else {
        decryptor(self.privateKeyRef);
    }

    return clearText;
}

- (NSString *)sign64:(NSString *)b64message {
    NSData *data = [[NSData alloc] initWithBase64EncodedString:b64message options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSString *encodedSignature = [self _sign: data];
    return encodedSignature;
}

- (NSString *)sign:(NSString *)message {
    NSData* data = [message dataUsingEncoding:NSUTF8StringEncoding];
    NSString *encodedSignature = [self _sign: data];
    return encodedSignature;
}

- (NSString *)_sign:(NSData *)messageBytes {
    __block NSString *encodedSignature = nil;

    void(^signer)(SecKeyRef) = ^(SecKeyRef privateKey) {
        SecKeyAlgorithm algorithm = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512;

        BOOL canSign = SecKeyIsAlgorithmSupported(privateKey,
                                                kSecKeyOperationTypeSign,
                                                algorithm);

        NSData* signature = nil;

        if (canSign) {
            CFErrorRef error = NULL;
            signature = (NSData*)CFBridgingRelease(SecKeyCreateSignature(privateKey,
                                                                         algorithm,
                                                                         (__bridge CFDataRef)messageBytes,
                                                                         &error));
            if (!signature) {
              NSError *err = CFBridgingRelease(error);
              NSLog(@"error: %@", err);
            }
        }

        encodedSignature = [signature base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    };

    if (self.keyTag) {
        [self performWithPrivateKeyTag:self.keyTag block:signer];
    } else {
        signer(self.privateKeyRef);
    }

    return encodedSignature;
}

- (BOOL)verify64:(NSString *)encodedSignature withMessage:(NSString *)b64message {
    NSData *messageBytes = [[NSData alloc] initWithBase64EncodedString:b64message options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSData *signatureBytes = [[NSData alloc] initWithBase64EncodedString:encodedSignature options:NSDataBase64DecodingIgnoreUnknownCharacters];
    return [self _verify: signatureBytes withMessage: messageBytes];
}

- (BOOL)verify:(NSString *)encodedSignature withMessage:(NSString *)message {
    NSData *messageBytes = [message dataUsingEncoding:NSUTF8StringEncoding];
    NSData *signatureBytes = [[NSData alloc] initWithBase64EncodedString:encodedSignature options:NSDataBase64DecodingIgnoreUnknownCharacters];
    return [self _verify: signatureBytes withMessage: messageBytes];
}

- (BOOL)_verify:(NSData *)signatureBytes withMessage:(NSData *)messageBytes {
    __block BOOL result = NO;

    void(^verifier)(SecKeyRef) = ^(SecKeyRef publicKey) {
        SecKeyAlgorithm algorithm = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512;

        BOOL canVerify = SecKeyIsAlgorithmSupported(publicKey,
                                                    kSecKeyOperationTypeVerify,
                                                    algorithm);

        if (canVerify) {
            CFErrorRef error = NULL;
            result = SecKeyVerifySignature(publicKey,
                                           algorithm,
                                           (__bridge CFDataRef)messageBytes,
                                           (__bridge CFDataRef)signatureBytes,
                                           &error);
            if (!result) {
                NSError *err = CFBridgingRelease(error);
                NSLog(@"error: %@", err);
            }
        }
    };

    if (self.keyTag) {
        [self performWithPublicKeyTag:self.keyTag block:verifier];
    } else {
        verifier(self.publicKeyRef);
    }

    return result;
}

- (void)performWithPrivateKeyTag:(NSString *)keyTag block:(SecKeyPerformBlock)performBlock {
    NSData *tag = [keyTag dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *getquery = @{ (id)kSecClass: (id)kSecClassKey,
                                (id)kSecAttrApplicationTag: tag,
                                (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
                                (id)kSecReturnRef: @YES,
                                };

    SecKeyRef key = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)getquery,
                                          (CFTypeRef *)&key);

    if (status != errSecSuccess) {
        NSLog(@"error accessing the key");
    } else {
        if (performBlock) { performBlock(key); }
        if (key) { CFRelease(key); }
    }
}

- (void)performWithPublicKeyTag:(NSString *)tag block:(SecKeyPerformBlock)performBlock {
    [self performWithPrivateKeyTag:tag block:^(SecKeyRef key) {
        SecKeyRef publicKey = SecKeyCopyPublicKey(key);

        if (performBlock) { performBlock(publicKey); }
        if (publicKey) { CFRelease(publicKey); }
    }];
}

- (NSString *) externalRepresentationForPublicKey:(SecKeyRef)key {
    NSData *keyData = [self dataForKey:key];
    return [RSAFormatter PEMFormattedPublicKey:keyData];
}

- (NSString *) externalRepresentationForPrivateKey:(SecKeyRef)key {
    NSData *keyData = [self dataForKey:key];
    return [RSAFormatter PEMFormattedPrivateKey:keyData];
}

- (NSString *) externalASN1Representation:(SecKeyRef)key {
    NSData *keyData = [self dataForKey:key];
    return [RSAFormatter ASN1FormattedPublicKey:keyData];
}


- (NSData *)dataForKey:(SecKeyRef)key {
    CFErrorRef error = NULL;
    NSData * keyData = (NSData *)CFBridgingRelease(SecKeyCopyExternalRepresentation(key, &error));
    
    if (!keyData) {
        NSError *err = CFBridgingRelease(error);
        NSLog(@"%@", err);
    }
    
    return keyData;
}

@end

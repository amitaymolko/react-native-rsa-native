#import "RSANative.h"

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

- (void)generate {
    NSMutableDictionary *privateKeyAttributes = [NSMutableDictionary dictionary];

    if (self.keyTag) {
        NSData *tag = [self.keyTag dataUsingEncoding:NSUTF8StringEncoding];

        privateKeyAttributes[(id)kSecAttrIsPermanent] = @YES; // store in keychain
        privateKeyAttributes[(id)kSecAttrApplicationTag] = tag;
    }

    NSDictionary *attributes =
    @{ (id)kSecAttrKeyType:       (id)kSecAttrKeyTypeRSA,
       (id)kSecAttrKeySizeInBits: @2048,
       (id)kSecPrivateKeyAttrs:   privateKeyAttributes
       };

    CFErrorRef error = NULL;
    SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes, &error);

    if (!privateKey) {
        NSError *err = CFBridgingRelease(error);
        NSLog(@"%@", err);
    }

    if (!self.keyTag) { // no keychain being used, store reference to keys for later use
        _privateKeyRef = privateKey;
        _privateKey = [self externalRepresentationForKey:self.privateKeyRef];

        _publicKeyRef = SecKeyCopyPublicKey(privateKey);
        _publicKey = [self externalRepresentationForKey:self.publicKeyRef];
    }
}

- (NSString *)encodedPublicKey {
    if (self.keyTag) {
        __block NSData *keyData = nil;

        [self performWithPublicKeyTag:self.keyTag block:^(SecKeyRef publicKey) {
            CFErrorRef error = NULL;
            keyData = (NSData *)CFBridgingRelease(SecKeyCopyExternalRepresentation(publicKey, &error));

            if (!keyData) {
                NSError *err = CFBridgingRelease(error);
                NSLog(@"%@", err);
            }
        }];

        return [keyData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    }

    return self.publicKey;
}

- (NSString *)encodedPrivateKey {
    if (self.keyTag) {
        __block NSData *keyData = nil;

        [self performWithPrivateKeyTag:self.keyTag block:^(SecKeyRef privateKey) {
            CFErrorRef error = NULL;
            keyData = (NSData *)CFBridgingRelease(SecKeyCopyExternalRepresentation(privateKey, &error));

            if (!keyData) {
                NSError *err = CFBridgingRelease(error);
                NSLog(@"%@", err);
            }
        }];

        return [keyData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    }

    return self.privateKey;
}

- (void)setPublicKey:(NSString *)publicKey {
    NSDictionary* options = @{(id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
                              (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPublic,
                              (id)kSecAttrKeySizeInBits: @2048,
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
    NSDictionary* options = @{(id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
                              (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPrivate,
                              (id)kSecAttrKeySizeInBits: @2048,
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

- (NSString *)encrypt:(NSString *)message {
    __block NSData *cipherText = nil;

    void(^encryptor)(SecKeyRef) = ^(SecKeyRef publicKey) {
        BOOL canEncrypt = SecKeyIsAlgorithmSupported(publicKey,
                                                     kSecKeyOperationTypeEncrypt,
                                                     kSecKeyAlgorithmRSAEncryptionOAEPSHA512);
        NSData *plainText = [message dataUsingEncoding:NSUTF8StringEncoding];
        canEncrypt &= ([plainText length] < (SecKeyGetBlockSize(publicKey)-130));

        if (canEncrypt) {
            CFErrorRef error = NULL;
            cipherText = (NSData *)CFBridgingRelease(SecKeyCreateEncryptedData(publicKey,
                                                                               kSecKeyAlgorithmRSAEncryptionOAEPSHA512,
                                                                               (__bridge CFDataRef)plainText,
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

    return [cipherText base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
}

- (NSString *)decrypt:(NSString *)encodedMessage {
    __block NSData *clearText = nil;

    void(^decryptor)(SecKeyRef) = ^(SecKeyRef privateKey) {
        NSData *cipherText = [[NSData alloc] initWithBase64EncodedString:encodedMessage options:NSDataBase64DecodingIgnoreUnknownCharacters];

        BOOL canDecrypt = SecKeyIsAlgorithmSupported(privateKey,
                                                     kSecKeyOperationTypeDecrypt,
                                                     kSecKeyAlgorithmRSAEncryptionOAEPSHA512);
        canDecrypt &= ([cipherText length] == SecKeyGetBlockSize(privateKey));

        if (canDecrypt) {
            CFErrorRef error = NULL;
            clearText = (NSData *)CFBridgingRelease(SecKeyCreateDecryptedData(privateKey,
                                                                              kSecKeyAlgorithmRSAEncryptionOAEPSHA512,
                                                                              (__bridge CFDataRef)cipherText,
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

    return [[NSString alloc] initWithData:clearText encoding:NSUTF8StringEncoding];
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

- (NSString *)externalRepresentationForKey:(SecKeyRef)key {
    CFErrorRef error = NULL;
    NSData * keyData = (NSData *)CFBridgingRelease(SecKeyCopyExternalRepresentation(key, &error));

    if (!keyData) {
        NSError *err = CFBridgingRelease(error);
        NSLog(@"%@", err);
    }

    return [keyData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
}

@end

#import "RSANative.h"

// Code largely based on practices as defined by:
// https://developer.apple.com/library/content/documentation/Security/Conceptual/CertKeyTrustProgGuide/KeyRead.html#//apple_ref/doc/uid/TP40001358-CH222-SW1

// TODO: need to pass the tag key in during generation of the keypair for identifying
// extracting the keys from the keychain

static NSString *kKeyPairTagIdentifier = @"com.example.keys.mykey";

typedef void (^SecKeyPerformBlock)(SecKeyRef key);

@implementation RSANative

- (void)generate {
    NSData *tag = [kKeyPairTagIdentifier dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *attributes =
    @{ (id)kSecAttrKeyType:               (id)kSecAttrKeyTypeRSA,
       (id)kSecAttrKeySizeInBits:         @2048,
       (id)kSecPrivateKeyAttrs:
           @{ (id)kSecAttrIsPermanent:    @YES,
              (id)kSecAttrApplicationTag: tag,
              },
       };

    CFErrorRef error = NULL;
    SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes, &error);

    if (!privateKey) {
        NSError *err = CFBridgingRelease(error);
        NSLog(@"%@", err);
    }
}

- (NSString *)encodedPublicKey {
    __block NSData *keyData = nil;

    [self performWithPublicKey:^(SecKeyRef publicKey) {
        CFErrorRef error = NULL;
        keyData = (NSData *)CFBridgingRelease(SecKeyCopyExternalRepresentation(publicKey, &error));

        if (!keyData) {
            NSError *err = CFBridgingRelease(error);
            NSLog(@"%@", err);
        }
    }];

    return [keyData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
}

- (NSString *)encodedPrivateKey {
    __block NSData *keyData = nil;

    [self performWithPrivateKey:^(SecKeyRef privateKey) {
        CFErrorRef error = NULL;
        keyData = (NSData *)CFBridgingRelease(SecKeyCopyExternalRepresentation(privateKey, &error));

        if (!keyData) {
            NSError *err = CFBridgingRelease(error);
            NSLog(@"%@", err);
        }
    }];

    return [keyData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
}

- (void)setPublicKey:(NSString *)pubKey {
    // external
}
- (void)setPrivateKey:(NSString *)privKey {
    // external
}

- (NSString *)encrypt:(NSString *)message {
    __block NSData *cipherText = nil;

    [self performWithPublicKey:^(SecKeyRef publicKey) {
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
    }];

    return [cipherText base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
}

- (NSString *)decrypt:(NSString *)encodedMessage {
    __block NSData *clearText = nil;

    [self performWithPrivateKey:^(SecKeyRef privateKey) {
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
    }];

    return [[NSString alloc] initWithData:clearText encoding:NSUTF8StringEncoding];
}

- (void)performWithPrivateKey:(SecKeyPerformBlock)performBlock {
    NSData *tag = [kKeyPairTagIdentifier dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *getquery = @{ (id)kSecClass: (id)kSecClassKey,
                                (id)kSecAttrApplicationTag: tag,
                                (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
                                (id)kSecReturnRef: @YES,
                                };

    SecKeyRef key = NULL;
    NSData *clearText = nil;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)getquery,
                                          (CFTypeRef *)&key);

    if (performBlock) { performBlock(key); }
    if (key) { CFRelease(key); }
}

- (void)performWithPublicKey:(SecKeyPerformBlock)performBlock {
    [self performWithPrivateKey:^(SecKeyRef key) {
        SecKeyRef publicKey = SecKeyCopyPublicKey(key);

        if (performBlock) { performBlock(publicKey); }
        if (publicKey) { CFRelease(publicKey); }
    }];
}

@end

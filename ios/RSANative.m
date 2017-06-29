#import "RSANative.h"

@implementation RSANative

- (void)generate {
    NSData* tag = [@"com.example.keys.mykey" dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary* attributes =
    @{ (id)kSecAttrKeyType:               (id)kSecAttrKeyTypeRSA,
       (id)kSecAttrKeySizeInBits:         @2048,
       (id)kSecPrivateKeyAttrs:
           @{ (id)kSecAttrIsPermanent:    @YES,
              (id)kSecAttrApplicationTag: tag,
              },
       };

    CFErrorRef error = NULL;
    _privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes,
                                                 &error);

    if (!self.privateKey) {
        NSError *err = CFBridgingRelease(error);
        NSLog(@"%@", err);
    }

    _publicKey = SecKeyCopyPublicKey(self.privateKey);
}

//-(NSString *) pemFormat:(NSString *) header :(NSString *) key {
//    return [NSString stringWithFormat:@"-----BEGIN %@ KEY-----\n%@\n-----END %@ KEY-----", header, key, header];
//}

- (NSString *)getPublicKey {
    CFErrorRef error = NULL;
    NSData* keyData = (NSData*)CFBridgingRelease(SecKeyCopyExternalRepresentation(self.publicKey, &error));

    if (!keyData) {
        NSError *err = CFBridgingRelease(error);  // ARC takes ownership
        NSLog(@"%@", err);
    }

    return [keyData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
}

- (NSString *)getPrivateKey {
    CFErrorRef error = NULL;
    NSData* keyData = (NSData*)CFBridgingRelease(SecKeyCopyExternalRepresentation(self.privateKey, &error));

    if (!keyData) {
        NSError *err = CFBridgingRelease(error);  // ARC takes ownership
        NSLog(@"%@", err);
    }

    return [keyData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
}

- (void)setPublicKey:(NSString *)pubKey {
    // external
}
- (void)setPrivateKey:(NSString *)privKey {
    // external
}

- (NSString *)encrypt:(NSString *)message {
    NSData* tag = [@"com.example.keys.mykey" dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *getquery = @{ (id)kSecClass: (id)kSecClassKey,
                                (id)kSecAttrApplicationTag: tag,
                                (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
                                (id)kSecReturnRef: @YES,
                                };

    SecKeyRef key = NULL;
    NSData* cipherText = nil;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)getquery,
                                          (CFTypeRef *)&key);
    _privateKey = key;
    _publicKey = SecKeyCopyPublicKey(self.privateKey);

    if (status!=errSecSuccess) {
        NSLog(@"error accessing the key");
    } else  {
        SecKeyAlgorithm algorithm = kSecKeyAlgorithmRSAEncryptionOAEPSHA512;

        BOOL canEncrypt = SecKeyIsAlgorithmSupported(self.publicKey,
                                                     kSecKeyOperationTypeEncrypt,
                                                     algorithm);
        NSData* plainText = [message dataUsingEncoding:NSUTF8StringEncoding];
        canEncrypt &= ([plainText length] < (SecKeyGetBlockSize(self.publicKey)-130));

        if (canEncrypt) {
            CFErrorRef error = NULL;
            cipherText = (NSData*)CFBridgingRelease(SecKeyCreateEncryptedData(self.publicKey,
                                                                              algorithm,
                                                                              (__bridge CFDataRef)plainText,
                                                                              &error));
            if (!cipherText) {
                NSError *err = CFBridgingRelease(error);
                NSLog(@"%@", err);
            }
        }
    }

    if (key) { CFRelease(key); }

    return [cipherText base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
}

- (NSString *)decrypt:(NSString *)encodedMessage {
    NSData* tag = [@"com.example.keys.mykey" dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *getquery = @{ (id)kSecClass: (id)kSecClassKey,
                                (id)kSecAttrApplicationTag: tag,
                                (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
                                (id)kSecReturnRef: @YES,
                                };

    SecKeyRef key = NULL;
    NSData* clearText = nil;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)getquery,
                                          (CFTypeRef *)&key);
    _privateKey = key;

    if (status!=errSecSuccess) {
        NSLog(@"error accessing the key");
    } else  {
        SecKeyAlgorithm algorithm = kSecKeyAlgorithmRSAEncryptionOAEPSHA512;
        NSData * cipherText = [[NSData alloc] initWithBase64EncodedString:encodedMessage options:NSDataBase64DecodingIgnoreUnknownCharacters];

        BOOL canDecrypt = SecKeyIsAlgorithmSupported(self.privateKey,
                                                     kSecKeyOperationTypeDecrypt,
                                                     algorithm);
        canDecrypt &= ([cipherText length] == SecKeyGetBlockSize(self.privateKey));

        if (canDecrypt) {
            CFErrorRef error = NULL;
            clearText = (NSData*)CFBridgingRelease(SecKeyCreateDecryptedData(self.privateKey,
                                                                             algorithm,
                                                                             (__bridge CFDataRef)cipherText,
                                                                             &error));
            if (!clearText) {
                NSError *err = CFBridgingRelease(error);
                NSLog(@"%@", err);
            }
        }
    }

    return [[NSString alloc] initWithData:clearText encoding:NSUTF8StringEncoding];
}

@end

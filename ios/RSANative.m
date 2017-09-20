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
        _publicKeyRef = SecKeyCopyPublicKey(privateKey);
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

    return [self externalRepresentationForPublicKey:self.privateKeyRef];
}

- (void)setPublicKey:(NSString *)publicKey {
    publicKey = [RSAFormatter stripHeaders: publicKey];
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
    privateKey = [RSAFormatter stripHeaders: privateKey];

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
    NSData *data = [message dataUsingEncoding:NSUTF8StringEncoding];
    void(^encryptor)(SecKeyRef) = ^(SecKeyRef publicKey) {
        BOOL canEncrypt = SecKeyIsAlgorithmSupported(publicKey,
                                                     kSecKeyOperationTypeEncrypt,
                                                     kSecKeyAlgorithmRSAEncryptionPKCS1);

        const uint8_t *srcbuf = (const uint8_t *)[data bytes];
        size_t srclen = (size_t)data.length;
        
        size_t block_size = SecKeyGetBlockSize(publicKey) * sizeof(uint8_t);
        void *outbuf = malloc(block_size);
        size_t src_block_size = block_size - 11;
        NSMutableData *ret = [[NSMutableData alloc] init];
        for(int idx=0; idx<srclen; idx+=src_block_size){
            //NSLog(@"%d/%d block_size: %d", idx, (int)srclen, (int)block_size);
            size_t data_len = srclen - idx;
            if(data_len > src_block_size){
                data_len = src_block_size;
            }
            
            size_t outlen = block_size;
            OSStatus status = noErr;
            

            status = SecKeyEncrypt(publicKey,
                                kSecPaddingPKCS1,
                                srcbuf + idx,
                                data_len,
                                outbuf,
                                &outlen
                                );
            
            if (status != 0) {
                NSLog(@"SecKeyEncrypt fail. Error Code: %d", status);
                ret = nil;
                break;
            }else{
                [ret appendBytes:outbuf length:outlen];
            }
        }
        
        free(outbuf);
        cipherText = ret;
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
    NSData *data = [[NSData alloc] initWithBase64EncodedString:encodedMessage options:NSDataBase64DecodingIgnoreUnknownCharacters];

    void(^decryptor)(SecKeyRef) = ^(SecKeyRef privateKey) {
        const uint8_t *srcbuf = (const uint8_t *)[data bytes];
        size_t srclen = (size_t)data.length;
        
        size_t block_size = SecKeyGetBlockSize(privateKey) * sizeof(uint8_t);
        UInt8 *outbuf = malloc(block_size);
        size_t src_block_size = block_size;
        
        NSMutableData *ret = [[NSMutableData alloc] init];
        for(int idx=0; idx<srclen; idx+=src_block_size){
            //NSLog(@"%d/%d block_size: %d", idx, (int)srclen, (int)block_size);
            size_t data_len = srclen - idx;
            if(data_len > src_block_size){
                data_len = src_block_size;
            }
            
            size_t outlen = block_size;
            OSStatus status = noErr;
            status = SecKeyDecrypt(privateKey,
                                kSecPaddingNone,
                                srcbuf + idx,
                                data_len,
                                outbuf,
                                &outlen
                                );
            if (status != 0) {
                NSLog(@"SecKeyEncrypt fail. Error Code: %d", status);
                ret = nil;
                break;
            }else{
                //the actual decrypted data is in the middle, locate it!
                int idxFirstZero = -1;
                int idxNextZero = (int)outlen;
                for ( int i = 0; i < outlen; i++ ) {
                    if ( outbuf[i] == 0 ) {
                        if ( idxFirstZero < 0 ) {
                            idxFirstZero = i;
                        } else {
                            idxNextZero = i;
                            break;
                        }
                    }
                }
                
                [ret appendBytes:&outbuf[idxFirstZero+1] length:idxNextZero-idxFirstZero-1];
            }
        }
        
        free(outbuf);
        clearText = ret;
    };

    if (self.keyTag) {
        [self performWithPrivateKeyTag:self.keyTag block:decryptor];
    } else {
        decryptor(self.privateKeyRef);
    }

    return [[NSString alloc] initWithData:clearText encoding:NSUTF8StringEncoding];
}

- (NSString *)sign:(NSString *)message {
    __block NSString *encodedSignature = nil;

    void(^signer)(SecKeyRef) = ^(SecKeyRef privateKey) {
        SecKeyAlgorithm algorithm = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512;

        BOOL canSign = SecKeyIsAlgorithmSupported(privateKey,
                                                kSecKeyOperationTypeSign,
                                                algorithm);

        NSData* data = [message dataUsingEncoding:NSUTF8StringEncoding];
        NSData* signature = nil;

        if (canSign) {
            CFErrorRef error = NULL;
            signature = (NSData*)CFBridgingRelease(SecKeyCreateSignature(privateKey,
                                                                         algorithm,
                                                                         (__bridge CFDataRef)data,
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

- (BOOL)verify:(NSString *)encodedSignature withMessage:(NSString *)message {
    __block BOOL result = NO;

    void(^verifier)(SecKeyRef) = ^(SecKeyRef publicKey) {
        SecKeyAlgorithm algorithm = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512;

        BOOL canVerify = SecKeyIsAlgorithmSupported(publicKey,
                                                    kSecKeyOperationTypeVerify,
                                                    algorithm);
        NSData* data = [message dataUsingEncoding:NSUTF8StringEncoding];
        NSData* signature = [[NSData alloc] initWithBase64EncodedString:encodedSignature options:NSDataBase64DecodingIgnoreUnknownCharacters];

        if (canVerify) {
            CFErrorRef error = NULL;
            result = SecKeyVerifySignature(publicKey,
                                           algorithm,
                                           (__bridge CFDataRef)data,
                                           (__bridge CFDataRef)signature,
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

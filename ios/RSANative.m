#import "RSANative.h"

@implementation RSANative

- (void) generate {
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

- (NSString *) getPublicKey {
    CFErrorRef error = NULL;
    NSData* keyData = (NSData*)CFBridgingRelease(SecKeyCopyExternalRepresentation(self.publicKey, &error));

    if (!keyData) {
        NSError *err = CFBridgingRelease(error);  // ARC takes ownership
        NSLog(@"%@", err);
    }

    return [[NSString alloc] initWithData:keyData encoding:NSUTF8StringEncoding];
}

- (NSString *) getPrivateKey {
    CFErrorRef error = NULL;
    NSData* keyData = (NSData*)CFBridgingRelease(SecKeyCopyExternalRepresentation(self.privateKey, &error));

    if (!keyData) {
        NSError *err = CFBridgingRelease(error);  // ARC takes ownership
        NSLog(@"%@", err);
    }

    return [[NSString alloc] initWithData:keyData encoding:NSUTF8StringEncoding];
}

- (void) setPublicKey: (NSString *) pubKey {
//    NSMutableString *dataString = [[NSMutableString alloc] initWithString:pubKey];
//
//    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"(-{5,}BEGIN (RSA )?PUBLIC KEY-{5,})|(-{5,}END (RSA )?PUBLIC KEY-{5,})|\n|\r"
//                                                                           options:0
//                                                                             error:nil];
//    [regex replaceMatchesInString:dataString
//                          options:0
//                            range:NSMakeRange(0, dataString.length)
//                     withTemplate:@""];
//
//    NSData *pub = [NSData MIH_dataByBase64DecodingString:dataString];
//    self._publicKey = [[MIHRSAPublicKey alloc] initWithData:pub];
}
- (void) setPrivateKey: (NSString *) privKey {
//    NSData *pem = [privKey dataUsingEncoding:NSUTF8StringEncoding];
//    self._privateKey = [[MIHRSAPrivateKey alloc] initWithData:pem];
}

- (NSString *) encrypt: (NSString *) message {
    SecKeyAlgorithm algorithm = kSecKeyAlgorithmRSAEncryptionOAEPSHA512;

    BOOL canEncrypt = SecKeyIsAlgorithmSupported(self.publicKey,
                                                 kSecKeyOperationTypeEncrypt,
                                                 algorithm);
    NSData* plainText = [message dataUsingEncoding:NSUTF8StringEncoding];
    canEncrypt &= ([plainText length] < (SecKeyGetBlockSize(self.publicKey)-130));

    NSData* cipherText = nil;
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

    return [cipherText base64EncodedStringWithOptions:0];
}

- (NSString *) decrypt: (NSString *) encodedMessage {
    SecKeyAlgorithm algorithm = kSecKeyAlgorithmRSAEncryptionOAEPSHA512;
    NSData * cipherText = [[NSData alloc] initWithBase64EncodedString:encodedMessage options:0];

    BOOL canDecrypt = SecKeyIsAlgorithmSupported(self.privateKey,
                                                 kSecKeyOperationTypeDecrypt,
                                                 algorithm);
    canDecrypt &= ([encodedMessage length] == SecKeyGetBlockSize(self.privateKey));

    NSData* clearText = nil;
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

    return [[NSString alloc] initWithData:clearText encoding:NSUTF8StringEncoding];
}

@end

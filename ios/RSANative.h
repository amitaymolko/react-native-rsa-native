//
//  RSA.h
//  RNRSA
//
//  Created by Amitay Molko on 24/06/2017.
//  Copyright © 2017 Facebook. All rights reserved.
//

@import Foundation;

@interface RSANative : NSObject

@property (nonatomic) NSString *publicKey;
@property (nonatomic) NSString *privateKey;

- (instancetype)initWithKeyTag:(NSString *)keyTag;

- (void)generate:(int)keySize withDigest:(NSString *)digest;
- (void)deletePrivateKey;

- (NSString *)encodedPublicKey;
- (NSString *)encodedPrivateKey;

- (NSString *)encrypt:(NSString *)message;
- (NSString *)decrypt:(NSString *)encodedMessage;

- (NSString *)encrypt64:(NSString *)message;
- (NSString *)decrypt64:(NSString *)encodedMessage;

- (NSData *)_encrypt:(NSData *)message;
- (NSData *)_decrypt:(NSData *)encodedMessage;

- (NSString *)sign:(NSString *)message withAlgorithm:(NSString *)algorithm;
- (BOOL)verify:(NSString *)signature withMessage:(NSString *)message;

- (NSString *)sign64:(NSString *)b64message;
- (BOOL)verify64:(NSString *)signature withMessage:(NSString *)b64message;

- (NSString *)_sign:(NSData *)messageBytes;
- (BOOL)_verify:(NSData *)signatureBytes withMessage:(NSData *)messageBytes;

@end

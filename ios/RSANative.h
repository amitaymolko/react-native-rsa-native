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

- (void)generate;
- (void)deletePrivateKey;

- (NSString *)encodedPublicKey;
- (NSString *)encodedPrivateKey;

- (NSString *)encrypt:(NSString *)message;
- (NSString *)decrypt:(NSString *)encodedMessage;

- (NSString *)encrypt64:(NSString *)message;
- (NSString *)decrypt64:(NSString *)encodedMessage;

- (NSString *)sign:(NSString *)message;
- (BOOL)verify:(NSString *)signature withMessage:(NSString *)message;

@end

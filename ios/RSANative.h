//
//  RSA.h
//  RNRSA
//
//  Created by Amitay Molko on 24/06/2017.
//  Copyright © 2017 Facebook. All rights reserved.
//

@import Foundation;

@interface RSANative : NSObject

- (void)generate;

- (NSString *)encodedPublicKey;
- (NSString *)encodedPrivateKey;
- (void)setPublicKey: (NSString *)pubKey;
- (void)setPrivateKey: (NSString *)privKey;

- (NSString *)encrypt:(NSString *)message;
- (NSString *)decrypt:(NSString *)encodedMessage;

@end

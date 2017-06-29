//
//  RSA.h
//  RNRSA
//
//  Created by Amitay Molko on 24/06/2017.
//  Copyright © 2017 Facebook. All rights reserved.
//

@import Foundation;

@interface RSANative : NSObject

@property (nonatomic) SecKeyRef publicKey;
@property (nonatomic) SecKeyRef privateKey;

- (void) generate;

- (NSString *) getPublicKey;
- (NSString *) getPrivateKey;
- (void) setPublicKey: (NSString *) pubKey;
- (void) setPrivateKey: (NSString *) privKey;

- (NSString *) encrypt: (NSString *) message;
- (NSString *) decrypt: (NSString *) encodedMessage;

@end

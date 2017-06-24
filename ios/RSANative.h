//
//  RSA.h
//  RNRSA
//
//  Created by Amitay Molko on 24/06/2017.
//  Copyright © 2017 Facebook. All rights reserved.
//

#import <Foundation/Foundation.h>
#import  <MIHCrypto/MIHRSAPublicKey.h>
#import  <MIHCrypto/MIHRSAPrivateKey.h>

@interface RSANative : NSObject

@property (nonatomic, retain) MIHRSAPublicKey *_publicKey;
@property (nonatomic, retain) MIHRSAPrivateKey *_privateKey;

- (void) generate;

- (NSString *) getPublicKey;
- (NSString *) getPrivateKey;
- (void) setPublicKey: (NSString *) pubKey;
- (void) setPrivateKey: (NSString *) privKey;

- (NSString *) encrypt: (NSString *) message;
- (NSString *) decrypt: (NSString *) encodedMessage;

@end




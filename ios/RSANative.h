//
//  RSA.h
//  RNRSA
//
//  Created by Amitay Molko on 24/06/2017.
//  Copyright © 2017 Facebook. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface RSANative : NSObject

@property (nonatomic, retain) NSString *publicKey;
@property (nonatomic, retain) NSString *privateKey;

- (void) generate;

- (NSString *) getPublicKey;
- (NSString *) getPrivateKey;
- (NSString *) setPublicKey;
- (NSString *) setPrivateKey;

- (NSString *) encode: (NSString *) message;
- (NSString *) decode: (NSString *) encodedMessage;

@end




//
//  RSAFormatter.h
//  RNRSA
//
//  Created by Amitay Molko on 30/06/2017.
//  Copyright © 2017 RNRSA. All rights reserved.
//

@import Foundation;

@interface RSAFormatter : NSObject

+ (NSString *) PEMFormattedPublicKey:(NSData *)publicKeyData;
+ (NSString *) PEMFormattedPrivateKey:(NSData *)privateKeyData;
+ (NSString *) stripHeaders: (NSString *)pemString;

@end

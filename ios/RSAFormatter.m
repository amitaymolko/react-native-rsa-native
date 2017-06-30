//
//  RNRSAFormatter.m
//  RNRSA
//
//  Created by Amitay Molko on 30/06/2017.
//  Copyright © 2017 RNRSA. All rights reserved.
//

#import "RSAFormatter.h"

@implementation RSAFormatter

static NSString *publicTag = @"RSA PUBLIC";
static NSString *privateTag = @"RSA PRIVATE";

+ (NSString *)PEMFormattedPublicKey:(NSData *)publicKeyData
{
    NSMutableData * encodedKey = [[NSMutableData alloc] init];
    [encodedKey appendData:publicKeyData];
    return [self pemFormat:encodedKey tag:publicTag];
}

+ (NSString *)PEMFormattedPrivateKey:(NSData *)privateKeyData
{
    NSMutableData * encodedKey = [[NSMutableData alloc] init];
    [encodedKey appendData:privateKeyData];
    return [self pemFormat:encodedKey tag:privateTag];
}

+(NSString *) pemFormat:(NSData *)encodedKey tag:(NSString *)tag
{
    return [NSString stringWithFormat:@"%@\n%@\n%@",
            [self headerForTag:tag],
            [encodedKey base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength],
            [self footerForTag:tag]
            ];
}

+ (NSString *) headerForTag:(NSString *)tag
{
    return [NSString stringWithFormat:@"-----BEGIN %@ KEY-----", tag ];
}

+ (NSString *) footerForTag:(NSString *)tag
{
    return [NSString stringWithFormat:@"-----END %@ KEY-----", tag];
}

+ (NSString *) stripHeaders: (NSString *)pemString
{
    NSRange spos;
    NSRange epos;
    spos = [pemString rangeOfString:[self headerForTag:privateTag]];
    if(spos.length > 0){
        epos = [pemString rangeOfString:[self footerForTag:privateTag]];
    }else{
        spos = [pemString rangeOfString:[self headerForTag:publicTag]];
        epos = [pemString rangeOfString:[self footerForTag:publicTag]];

    }
    if(spos.location != NSNotFound && epos.location != NSNotFound){
        NSUInteger s = spos.location + spos.length;
        NSUInteger e = epos.location;
        NSRange range = NSMakeRange(s, e-s);
        pemString = [pemString substringWithRange:range];
    }
    return pemString;
}

@end

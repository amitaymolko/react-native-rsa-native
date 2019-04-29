//
//  RNRSAFormatter.m
//  RNRSA
//
//  Created by Amitay Molko on 30/06/2017.
//  Copyright © 2017 RNRSA. All rights reserved.
//

#import "RSAFormatter.h"

@implementation RSAFormatter

static NSString *publicTag = @"PUBLIC";
static NSString *privateTag = @"PRIVATE";
static NSString *publicRsaTag = @"RSA PUBLIC";
static NSString *privateRsaTag = @"RSA PRIVATE";

+ (NSString *)PEMFormattedPublicKey:(NSData *)publicKeyData {
    NSMutableData * encodedKey = [[NSMutableData alloc] init];
    [encodedKey appendData:publicKeyData];
    return [self pemFormat:encodedKey tag:publicRsaTag];
}

+ (NSString *)PEMFormattedPrivateKey:(NSData *)privateKeyData {
    NSMutableData * encodedKey = [[NSMutableData alloc] init];
    [encodedKey appendData:privateKeyData];
    return [self pemFormat:encodedKey tag:privateRsaTag];
}

+ (NSString *)pemFormat:(NSData *)encodedKey tag:(NSString *)tag {
    return [NSString stringWithFormat:@"%@\n%@\n%@",
            [self headerForTag:tag],
            [encodedKey base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength],
            [self footerForTag:tag]
            ];
}

+ (NSString *)headerForTag:(NSString *)tag {
    return [NSString stringWithFormat:@"-----BEGIN %@ KEY-----", tag ];
}

+ (NSString *)footerForTag:(NSString *)tag {
    return [NSString stringWithFormat:@"-----END %@ KEY-----", tag];
}

+ (NSString *)stripHeaders:(NSString *)pemString {
    NSRange spos;
    NSRange epos;
    if ([pemString rangeOfString:[self headerForTag:privateRsaTag]].length > 0) {
        spos = [pemString rangeOfString:[self headerForTag:privateRsaTag]];
        epos = [pemString rangeOfString:[self footerForTag:privateRsaTag]];
    } else if ([pemString rangeOfString:[self headerForTag:publicRsaTag]].length > 0) {
        spos = [pemString rangeOfString:[self headerForTag:publicRsaTag]];
        epos = [pemString rangeOfString:[self footerForTag:publicRsaTag]];
    } else if ([pemString rangeOfString:[self headerForTag:privateTag]].length > 0) {
        spos = [pemString rangeOfString:[self headerForTag:privateTag]];
        epos = [pemString rangeOfString:[self footerForTag:privateTag]];
    } else if ([pemString rangeOfString:[self headerForTag:publicTag]].length > 0) {
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

#pragma mark - Java Helpers

// Java helpers to remove and add extra bits needed for java based backends
// Once it’s base 64 decoded it strips the ASN.1 encoding associated with the OID
// and sequence encoding that generally prepends the RSA key data. That leaves it
// with just the large numbers that make up the public key.
// Read this for a clear understanding of ANS.1, BER AND PCKS encodings
// https://stackoverflow.com/a/29707204/1460582

+ (NSString *)ASN1FormattedPublicKey:(NSData*)keyBits {
    
    static const unsigned char _encodedRSAEncryptionOID[15] = {
        
        /* Sequence of length 0xd made up of OID followed by NULL */
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
        
    };
    
    // That gives us the "BITSTRING component of a full DER
    // encoded RSA public key - We now need to build the rest
    
    unsigned char builder[15];
    NSMutableData * encKey = [[NSMutableData alloc] init];
    int bitstringEncLength;
    
    // When we get to the bitstring - how will we encode it?
    
    if  ([keyBits length ] + 1  < 128 )
        bitstringEncLength = 1 ;
    else
        bitstringEncLength = (int)(([keyBits length] + 1 ) / 256 ) + 2;
    
    // Overall we have a sequence of a certain length
    builder[0] = 0x30;    // ASN.1 encoding representing a SEQUENCE
    // Build up overall size made up of -
    // size of OID + size of bitstring encoding + size of actual key
    size_t i = sizeof(_encodedRSAEncryptionOID) + 2 + bitstringEncLength +
    [keyBits length];
    size_t j = encodeLength(&builder[1], i);
    [encKey appendBytes:builder length:j +1];
    
    // First part of the sequence is the OID
    [encKey appendBytes:_encodedRSAEncryptionOID
                 length:sizeof(_encodedRSAEncryptionOID)];
    
    // Now add the bitstring
    builder[0] = 0x03;
    j = encodeLength(&builder[1], [keyBits length] + 1);
    builder[j+1] = 0x00;
    [encKey appendBytes:builder length:j + 2];
    
    // Now the actual key
    [encKey appendData:keyBits];
    
    // base64 encode encKey and return
    return [encKey base64EncodedStringWithOptions:0];
    
}

size_t encodeLength(unsigned char * buf, size_t length) {
    
    // encode length in ASN.1 DER format
    if (length < 128) {
        buf[0] = length;
        return 1;
    }
    
    size_t i = (length / 256) + 1;
    buf[0] = i + 0x80;
    for (size_t j = 0 ; j < i; ++j) {
        buf[i - j] = length & 0xFF;
        length = length >> 8;
    }
    
    return i + 1;
}


@end

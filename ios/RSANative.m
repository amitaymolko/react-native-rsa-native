#import "RSANative.h"

#import  <MIHCrypto/MIHRSAKeyFactory.h>
#import  <MIHCrypto/MIHRSAPublicKey.h>
#import  <MIHCrypto/MIHRSAPrivateKey.h>
#import  <MIHCrypto/MIHKeyPair.h>
#import  <MIHCrypto/NSData+MIHConversion.h>
#import  <MIHCrypto/NSString+MIHConversion.h>

@implementation RSANative

@synthesize publicKey;
@synthesize privateKey;

- (void) generate {
    MIHRSAKeyFactory *keyFactory = [[MIHRSAKeyFactory alloc] init];
    MIHKeyPair *keyPair = [keyFactory generateKeyPair];
    MIHRSAPublicKey *pubKey = keyPair.public;
    NSData *publicKeyData = [pubKey dataValue];
    self.publicKey = [publicKeyData MIH_base64EncodedString];

}

- (NSString *) getPublicKey {
    return @"";
}

- (NSString *) getPrivateKey {
    return @"";

}

- (NSString *) setPublicKey {
    return @"";

}
- (NSString *) setPrivateKey {
    return @"";

}

- (NSString *) encode: (NSString *) message {
    return @"";

}

- (NSString *) decode: (NSString *) encodedMessage {
    return @"";
}


@end

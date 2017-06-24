#import "RSANative.h"

#import  <MIHCrypto/MIHRSAKeyFactory.h>
#import  <MIHCrypto/MIHRSAPublicKey.h>
#import  <MIHCrypto/MIHRSAPrivateKey.h>
#import  <MIHCrypto/MIHKeyPair.h>
#import  <MIHCrypto/NSData+MIHConversion.h>
#import  <MIHCrypto/NSString+MIHConversion.h>

@implementation RSANative

@synthesize _publicKey;
@synthesize _privateKey;

- (void) generate {
    MIHRSAKeyFactory *keyFactory = [[MIHRSAKeyFactory alloc] init];
    MIHKeyPair *keyPair = [keyFactory generateKeyPair];
    
    self._publicKey = keyPair.public;
    self._privateKey = keyPair.private;
}

-(NSString *) pemFormat:(NSString *) header :(NSString *) key {
    return [NSString stringWithFormat:@"-----BEGIN %@ KEY-----\n%@\n-----END %@ KEY-----", header, key, header];
}

- (NSString *) getPublicKey {
    NSData *publicKeyData = [self._publicKey dataValue];
    return [self pemFormat:@"PUBLIC": [publicKeyData MIH_base64EncodedStringWithWrapWidth:64]];
}

- (NSString *) getPrivateKey {
    NSData *privateKeyData = [self._privateKey dataValue];
    return [[NSString alloc] initWithData:privateKeyData encoding:NSUTF8StringEncoding];
}

- (void) setPublicKey: (NSString *) pubKey {
    NSMutableString *dataString = [[NSMutableString alloc] initWithString:pubKey];
    
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"(-{5,}BEGIN (RSA )?PUBLIC KEY-{5,})|(-{5,}END (RSA )?PUBLIC KEY-{5,})|\n|\r"
                                                                           options:0
                                                                             error:nil];
    [regex replaceMatchesInString:dataString
                          options:0
                            range:NSMakeRange(0, dataString.length)
                     withTemplate:@""];
    
    NSData *pub = [NSData MIH_dataByBase64DecodingString:dataString];
    self._publicKey = [[MIHRSAPublicKey alloc] initWithData:pub];
    
}
- (void) setPrivateKey: (NSString *) privKey {
    NSData *pem = [privKey dataUsingEncoding:NSUTF8StringEncoding];
    self._privateKey = [[MIHRSAPrivateKey alloc] initWithData:pem];
}

- (NSString *) encrypt: (NSString *) message {
    NSError *error = nil;
    NSData *messageData = [message dataUsingEncoding:NSUTF8StringEncoding];
    NSData *encryptedData = [self._publicKey encrypt:messageData error:&error];
    return [encryptedData MIH_base64EncodedString];

}

- (NSString *) decrypt: (NSString *) encodedMessage {
    NSError *error = nil;
    NSData *messageData = [NSData MIH_dataByBase64DecodingString:encodedMessage];
    NSData *decryptedData = [self._privateKey decrypt:messageData error:&error];
    return [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
}

@end

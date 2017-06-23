// Heavily based off https://github.com/kuapay/iOS-Certificate--Key--and-Trust-Sample-Project

#import "RNRSA.h"
#import "NSData+Base64.h"
#import "NSString+Base64.h"

@implementation RNRSA

static const uint8_t publicKeyIdentifier[]		= "com.public.rnkeypari.temp";
static const uint8_t privateKeyIdentifier[]		= "com.private.RNRSA.temp";
static unsigned char oidSequence [] = { 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00 };


- (dispatch_queue_t)methodQueue
{
    return dispatch_get_main_queue();
}
RCT_EXPORT_MODULE()


- (NSString *)X509FormattedPublicKey:(NSData *)publicKeyData
{

    unsigned char builder[15];
    int bitstringEncLength;
    if  ([publicKeyData length] + 1  < 128 )
    {
        bitstringEncLength = 1 ;
    }
    else
    {
        bitstringEncLength = (([publicKeyData length ] + 1)/256) + 2;
    }
    
    builder[0] = 0x30;
    
    size_t i = sizeof(oidSequence) + 2 + bitstringEncLength + [publicKeyData length];
    size_t j = [self encode:&builder[1]
                     length:i];
    
    NSMutableData *encodedKey = [[NSMutableData alloc] init];
    
    [encodedKey appendBytes:builder
                     length:j + 1];
    
    [encodedKey appendBytes:oidSequence
                     length:sizeof(oidSequence)];
    
    builder[0] = 0x03;
    j = [self encode:&builder[1]
              length:[publicKeyData length] + 1];
    
    builder[j+1] = 0x00;
    [encodedKey appendBytes:builder
                     length:j + 2];
    
    [encodedKey appendData:publicKeyData];
    
    NSString *returnString = [NSString stringWithFormat:@"%@\n%@\n%@",
                              [self X509PublicHeader],
                              [encodedKey base64EncodedStringWithWrapWidth:[self PEMWrapWidth]],
                              [self X509PublicFooter]];
    
    
    return returnString;
}

- (NSString *)X509PublicHeader
{
    return @"-----BEGIN PUBLIC KEY-----";
}

- (NSString *)X509PublicFooter
{
    return @"-----END PUBLIC KEY-----";
}

- (NSString *)PEMPublicHeader
{
    return @"-----BEGIN RSA PUBLIC KEY-----";
}

- (NSString *)PEMPublicFooter
{
    return @"-----END RSA PUBLIC KEY-----";
}

- (NSString *)PEMPrivateHeader
{
    return @"-----BEGIN RSA PRIVATE KEY-----";
}


- (NSString *)PEMPrivateFooter
{
    return @"-----END RSA PRIVATE KEY-----";
}

- (NSUInteger)PEMWrapWidth
{
    return 64;
}

- (size_t)encode:(unsigned char *)buffer
          length:(size_t)length
{
    if (length < 128)
    {
        buffer[0] = length;
        return 1;
    }
    
    size_t i = (length / 256) + 1;
    buffer[0] = i + 0x80;
    for (size_t j = 0 ; j < i; ++j)
    {
        buffer[i - j] = length & 0xFF;
        length = length >> 8;
    }
    
    return i + 1;
}

- (NSString *)PEMFormattedPrivateKey:(NSData *)privateKeyData

{
    
    NSMutableData * encodedKey = [[NSMutableData alloc] init];
    [encodedKey appendData:privateKeyData];
    NSString *result = [NSString stringWithFormat:@"%@\n%@\n%@",
                        [self PEMPrivateHeader],
                        [encodedKey base64EncodedStringWithWrapWidth:[self PEMWrapWidth]],
                        [self PEMPrivateFooter]];
    
    
    return result;
}

- (NSString *)PEMFormattedPublicKey:(NSData *)publicKeyData

{
    
    NSMutableData * encodedKey = [[NSMutableData alloc] init];
    [encodedKey appendData:publicKeyData];
    NSString *result = [NSString stringWithFormat:@"%@\n%@\n%@",
                        [self PEMPublicHeader],
                        [encodedKey base64EncodedStringWithWrapWidth:[self PEMWrapWidth]],
                        [self PEMPublicFooter]];
    
    
    return result;
}


- (NSDictionary*) generateKeyPair:(NSUInteger)keySize {
    
    NSLog(@"Generating Key Pair");
    
    NSData* privateTag = [[NSData alloc] initWithBytes:privateKeyIdentifier length:sizeof(privateKeyIdentifier)];
    NSData* publicTag = [[NSData alloc] initWithBytes:publicKeyIdentifier length:sizeof(publicKeyIdentifier)];
    
    OSStatus sanityCheck = noErr;
    SecKeyRef publicKeyRef = NULL;
    SecKeyRef privateKeyRef = NULL;
    
    NSAssert( keySize == 512 || keySize == 1024 || keySize == 2048, @"%d is an invalid and unsupported key size.", keySize );
    
    
    // Container dictionaries.
    NSMutableDictionary * privateKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary * publicKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary * keyPairAttr = [[NSMutableDictionary alloc] init];
    
    // Set top level dictionary for the keypair.
    [keyPairAttr setObject:(id)kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
    [keyPairAttr setObject:[NSNumber numberWithUnsignedInteger:keySize] forKey:(id)kSecAttrKeySizeInBits];
    
    // Set the private key dictionary.
    [privateKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecAttrIsPermanent];
    [privateKeyAttr setObject:privateTag forKey:(id)kSecAttrApplicationTag];
    // See SecKey.h to set other flag values.
    
    // Set the public key dictionary.
    [publicKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecAttrIsPermanent];
    [publicKeyAttr setObject:publicTag forKey:(id)kSecAttrApplicationTag];
    // See SecKey.h to set other flag values.
    
    // Set attributes to top level dictionary.
    [keyPairAttr setObject:privateKeyAttr forKey:(id)kSecPrivateKeyAttrs];
    [keyPairAttr setObject:publicKeyAttr forKey:(id)kSecPublicKeyAttrs];
    
    sanityCheck = SecKeyGeneratePair((CFDictionaryRef)keyPairAttr, &publicKeyRef, &privateKeyRef);
    NSAssert( sanityCheck == noErr && publicKeyRef != NULL && privateKeyRef != NULL, @"Something really bad went wrong with generating the key pair." );
    
    NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
    
    // Set the public key query dictionary.
    [queryPublicKey setObject:(id)kSecClassKey forKey:(id)kSecClass];
    [queryPublicKey setObject:publicTag forKey:(id)kSecAttrApplicationTag];
    [queryPublicKey setObject:(id)kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
    [queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnData];
    
    // Get the key bits.
    CFTypeRef publicKeyBits = nil;
    sanityCheck = SecItemCopyMatching((CFDictionaryRef)queryPublicKey, &publicKeyBits);

    NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
    
    // Set the public key query dictionary.
    [queryPrivateKey setObject:(id)kSecClassKey forKey:(id)kSecClass];
    [queryPrivateKey setObject:privateTag forKey:(id)kSecAttrApplicationTag];
    [queryPrivateKey setObject:(id)kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
    [queryPrivateKey setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnData];
    
    // Get the key bits.
    CFTypeRef privateKeyBits = nil;
    sanityCheck = SecItemCopyMatching((CFDictionaryRef)queryPrivateKey, &privateKeyBits);
    
    
    NSString* publicKey = [self PEMFormattedPublicKey: (__bridge NSData *)publicKeyBits];
    NSString* privateKey = [self PEMFormattedPrivateKey: (__bridge NSData *)privateKeyBits];
    
    

    
    
    
    
    if (publicKeyRef) {
        CFRelease(publicKeyRef);
    }
    
    if (publicKeyBits) {
        CFRelease(publicKeyBits);
    }
    
    if (privateKeyRef) {
        CFRelease(privateKeyRef);
    }
    
    if (privateKeyBits) {
        CFRelease(privateKeyBits);
    }
    
    NSDictionary *keys = @{
      @"private" : privateKey,
      @"public" : publicKey
    };
    
    //NSLog(@"PUBLIC KEY IS: %@", publicKey);
    //NSLog(@"PRIVATE KEY IS: %@", privateKey);
    return keys;
   
}


RCT_EXPORT_METHOD(generate: (RCTResponseSenderBlock)callback) {
   
    callback(@[[self generateKeyPair: 2048]]);
    
}

@end
  
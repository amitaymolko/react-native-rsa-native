#import "Pbkdf2Rng.h"
#import <CommonCrypto/CommonKeyDerivation.h>

@implementation Pbkdf2Rng {
    int seedLength;
    uint8_t *seed;
    uint8_t *salt;
    int fillLength;
    int bits;
    int maxRead;
    int idx;
    uint8_t *bytes;
}

- (void)regenerate {
    size_t newBytesLen = fillLength+seedLength;
    uint8_t newBytes[fillLength + seedLength];
    for(int i=0; i<seedLength; i++) {
        seed[i] &= 0x7f;
    }
    
    CCKeyDerivationPBKDF(kCCPBKDF2, (const char *)seed, seedLength, salt, 1, kCCPRFHmacAlgSHA1, 1, newBytes, newBytesLen);
    for(int i=0; i<seedLength; i++) {
        seed[seedLength-i-1] = newBytes[fillLength+i];
    }
    uint8_t *tmp = NULL;
    if (idx >= 0) {
        tmp = malloc(idx+1);
        memcpy(tmp, bytes, idx+1);
    }
    memcpy(bytes, newBytes, fillLength);
    if (tmp) {
        memcpy(bytes+fillLength,tmp, idx+1);
        free(tmp);
    }
    idx += fillLength;
}

- (instancetype)init {
    self = [super init];
    seedLength = 16;
    unsigned char bytes[seedLength];
    for (int i=0; i<seedLength; i++) {
        bytes[i] = arc4random_uniform(256);
    }
    NSData *data = [NSData dataWithBytes:bytes length:seedLength];
    return [self initWithSeed:[[NSString alloc] initWithData:data encoding:NSISOLatin1StringEncoding] andNumBits:2048];
}

- (instancetype)initWithSeed:(NSString *)_seed andNumBits:(int)_bits {
    self = [super init];
    seedLength = 16;
    salt = malloc(1);
    salt[0] = 0;
    seed = malloc(seedLength);
    NSData *data = [_seed dataUsingEncoding:NSISOLatin1StringEncoding];
    for(int i=0; i<seedLength; i++) {
        seed[i] = (i<data.length) ? ((uint8_t *) data.bytes)[i] : 0;
    }
    bits = _bits;
    fillLength = 32*bits;
    maxRead = bits;
    bytes = malloc(fillLength + maxRead);
    idx = -1;
    [self regenerate];
    return self;
}

- (uint8_t*)nextBytes:(int)numBytes {
    if (numBytes > maxRead) {
        NSLog(@"Error: too many bytes requested (%d > %d)", numBytes, maxRead);
        return NULL;
    }
    uint8_t *ret = malloc(numBytes);
    if (idx < numBytes-1) {
        [self regenerate];
    }
    for (int i=0; i<numBytes; i++) {
        ret[i] = bytes[idx-i];
    }
    idx -= numBytes;
    return ret;
}

@end

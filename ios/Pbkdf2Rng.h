#ifndef Pbkdf2Rng_h
#define Pbkdf2Rng_h

@import Foundation;

@interface Pbkdf2Rng : NSObject

- (instancetype)initWithSeed:(NSString *)_seed andNumBits:(int)_bits;

- (uint8_t*)nextBytes:(int)bytes;

@end

#endif /* Pbkdf2Rng_h */

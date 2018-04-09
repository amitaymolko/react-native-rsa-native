#ifndef RSADeterministic_h
#define RSADeterministic_h

@import Foundation;

@interface RSADeterministic : NSObject

+ (NSDictionary*)generateDeterministic:(int)bits eInt:(unsigned long)eInt seed:(NSString *)seed;

@end

#endif /* RSADeterministic_h */

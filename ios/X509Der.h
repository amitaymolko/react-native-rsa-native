#ifndef X509Der_h
#define X509Der_h
@import Foundation;

#import "JKBigInteger.h"

@interface X509Der : NSObject
+(int)sizeInBytes:(int)a;
+(int)sizeInBits:(int)a;
+(NSData*)derEncodeLength:(int)length;
+(NSData*)derEncodeBigInt:(JKBigInteger*)item;
+(NSData*)derEncodeSequenceOfBigInts:(NSArray*)items;
+(NSString*)derEncodeRsaKey:(NSArray*)arr public:(bool)pub;
+(NSString*)nsDataToHexString:(NSData*)data;
@end

#endif /* X509Der_h */

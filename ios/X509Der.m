#import "X509Der.h"

@implementation X509Der
+(int)sizeInBytes:(int)a {
    return ([self sizeInBits:a]+7)/8;
}
+(int)sizeInBits:(int)a {
    for (int i=0; i<(sizeof(a)*8); i++) {
        if (a>>i == 0) {
            return i;
        }
    }
    return 32;
}
+(NSData*)derEncodeLength:(int)length {
    int bitsize = [self sizeInBits:length];
    int headerLen = 1;
    if (bitsize >= 8) {
        headerLen = 1+(bitsize+7)/8;
    }
    uint8_t data[headerLen];
    if (bitsize < 8) {
        assert(length < 0x7F);
        data[0] = length;
    } else {
        for (int i=0; i<headerLen; i++) {
            data[headerLen-1-i] = ((uint8_t *)(&length))[i];
        }
        data[0] = 0x80 | (headerLen-1);
    }
    return [NSData dataWithBytes:data length:headerLen];
}
+(NSData*)derEncodeBigInt:(JKBigInteger*)item {
    bool pad;
    NSString *itemHex = [item stringValueWithRadix:16];
    if (itemHex.length > 1) {
        unsigned int firstbyte;
        NSScanner *scanner = [NSScanner scannerWithString:[itemHex substringToIndex:2]];
        [scanner scanHexInt:&firstbyte];
        pad = ((0x80 & firstbyte) != 0);
    } else {
        pad = false;
    }
    int itemLength = [item countBytes] + ((pad) ? 1 : 0);
    if (itemLength == 0) {
        itemLength++;
    }
    uint8_t header = 0x02;
    NSMutableData *ret = [NSMutableData dataWithBytes:&header length:1];
    [ret appendData:[self derEncodeLength:itemLength]];
    unsigned char itemBytes[itemLength];
    itemBytes[0] = 0;
    [item toByteArrayUnsigned:itemBytes];
    if (pad) {
        uint8_t padding = 0;
        [ret appendData:[NSData dataWithBytes:&padding length:1]];
    }
    [ret appendData:[NSData dataWithBytes:itemBytes length:itemLength-((pad)?1:0)]];
    return ret;
}
+(NSString*)nsDataToHexString:(NSData*)data {
    const unsigned char* bytes = data.bytes;
    NSMutableString *ret = [[NSMutableString alloc] init];
    for (int i=0; i<data.length; i++) {
        [ret appendFormat:@"%02x ", bytes[i]];
    }
    return ret;
}
+(NSData*)derEncodeSequenceOfBigInts:(NSArray*)items {
    NSMutableData *payload = [[NSMutableData alloc] init];
    for (int i=0; i<[items count]; i++) {
        JKBigInteger *item = [items objectAtIndex:i];
        [payload appendData:[self derEncodeBigInt:item]];
    }
    uint8_t header = 0x30;
    NSMutableData *data = [NSMutableData dataWithBytes:&header length:1];
    [data appendData:[self derEncodeLength:(int)[payload length]]];
    [data appendData:payload];
    return data;
}
+(NSString*)derEncodeRsaKey:(NSArray*)arr public:(bool)pub {
    NSString *type = pub ? @"PUBLIC" : @"PRIVATE";
    NSString *fmt = @"-----%@ RSA %@ KEY-----";
    NSString *header = [NSString stringWithFormat:fmt, @"BEGIN", type];
    NSString *footer = [NSString stringWithFormat:fmt, @"END", type];
    NSData *data = [self derEncodeSequenceOfBigInts:arr];
    NSString *encoded = [data base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    encoded = [encoded stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    return [NSString stringWithFormat:@"%@\n%@\n%@\n", header, encoded, footer];
}
@end

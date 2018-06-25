//
//  X509Der_Test.m
//  Tests
//
//  Created by Admin Admin on 4/4/18.
//  Copyright © 2018 RNRSA. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "X509Der.h"

@interface X509Der_Test : XCTestCase

@end

@implementation X509Der_Test

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testEncodeSmallInt {
    NSString *expected = @"02 03 01 00 01 ";
    JKBigInteger *input = [[JKBigInteger alloc] initWithString:@"10001" andRadix:16];
    NSData *data = [X509Der derEncodeBigInt:input];
    NSString *actual = [X509Der nsDataToHexString:data];
    XCTAssertEqualObjects(expected, actual);
}
- (void)testEncodeBigInt2 {
    NSString *expected =
    @"02 81 80 09 4D 15 65 C5 61 80 C7 93 2C 53 52 4E FB 87 "
    @"25 BD 68 3C A8 0C 60 12 7E C9 AB 93 35 70 AD A0 "
    @"EA 81 E1 4C 8B 2A 73 DA 78 8B C4 6A 9B 7D 91 03 "
    @"62 2C 80 29 1C B1 38 B9 63 5C 96 2A 92 DF A8 14 "
    @"00 BF 5B BB 39 D1 06 3A 44 F1 21 AE B0 65 21 D0 "
    @"F0 E2 6F B5 C5 A7 3C 33 93 17 ED A8 BB 7D C3 CB "
    @"F4 F8 1A 48 5E B3 C0 AD F9 C2 DE 46 72 1C 5D 5D "
    @"A6 59 62 B9 95 E7 80 25 ED 3D D0 4C D6 58 67 E5 09 ";
    NSString *raw =
    @"094D1565C56180C7932C53524EFB8725BD683CA80C60127"
    @"EC9AB933570ADA0EA81E14C8B2A73DA788BC46A9B7D91036"
    @"22C80291CB138B9635C962A92DFA81400BF5BBB39D1063A4"
    @"4F121AEB06521D0F0E26FB5C5A73C339317EDA8BB7DC3CBF"
    @"4F81A485EB3C0ADF9C2DE46721C5D5DA65962B995E78025E"
    @"D3DD04CD65867E509";
    JKBigInteger *input = [[JKBigInteger alloc] initWithString:raw andRadix:16];
    NSData *data = [X509Der derEncodeBigInt:input];
    NSString *actual = [X509Der nsDataToHexString:data];
    XCTAssertEqualObjects([expected lowercaseString], actual);
}
- (void)testEncodeBigInt {
    NSString *expected =
    @"02 82 01 01 00 EB 50 63 99 F5 C6 12 F5 A6 7A 09 C1 19 2B 92 FA "
    @"B5 3D B2 85 20 D8 59 CE 0E F6 B7 D8 3D 40 AA 1C 1D CE 2C 07 20 "
    @"D1 5A 0F 53 15 95 CA D8 1B A5 D1 29 F9 1C C6 76 97 19 F1 43 58 "
    @"72 C4 BC D0 52 11 50 A0 26 3B 47 00 66 48 9B 91 8B FC A0 3C E8 "
    @"A0 E9 FC 2C 03 14 C4 B0 96 EA 30 71 7C 03 C2 8C A2 9E 67 8E 63 "
    @"D7 8A CA 1E 9A 63 BD B1 26 1E E7 A0 B0 41 AB 53 74 6D 68 B5 7B "
    @"68 BE F3 7B 71 38 28 38 C9 5D A8 55 78 41 A3 CA 58 10 9F 0B 4F "
    @"77 A5 E9 29 B1 A2 5D C2 D6 81 4C 55 DC 0F 81 CD 2F 4E 5D B9 5E "
    @"E7 0C 70 6F C0 2C 4F CA 35 8E A9 A8 2D 80 43 A4 76 11 19 55 80 "
    @"F8 94 58 E3 DA B5 59 2D EF E0 6C DE 1E 51 6A 6C 61 ED 78 C1 39 "
    @"77 AE 96 60 A9 19 2C A7 5C D7 29 67 FD 3A FA FA 1F 1A 2F F6 32 "
    @"5A 50 64 D8 47 02 8F 1E 6B 23 29 E8 57 2F 36 E7 08 A5 49 DD A3 "
    @"55 FC 74 A3 2F DD 8D BA 65 ";
    NSString *raw =
    @"00EB506399F5C612F5A67A09C1192B92FAB53DB28520D859CE0EF6B7D83"
    @"D40AA1C1DCE2C0720D15A0F531595CAD81BA5D129F91CC6769719F14358"
    @"72C4BCD0521150A0263B470066489B918BFCA03CE8A0E9FC2C0314C4B09"
    @"6EA30717C03C28CA29E678E63D78ACA1E9A63BDB1261EE7A0B041AB5374"
    @"6D68B57B68BEF37B71382838C95DA8557841A3CA58109F0B4F77A5E929B"
    @"1A25DC2D6814C55DC0F81CD2F4E5DB95EE70C706FC02C4FCA358EA9A82D"
    @"8043A47611195580F89458E3DAB5592DEFE06CDE1E516A6C61ED78C1397"
    @"7AE9660A9192CA75CD72967FD3AFAFA1F1A2FF6325A5064D847028F1E6B"
    @"2329E8572F36E708A549DDA355FC74A32FDD8DBA65";
    JKBigInteger *input = [[JKBigInteger alloc] initWithString:raw andRadix:16];
    NSData *data = [X509Der derEncodeBigInt:input];
    NSString *actual = [X509Der nsDataToHexString:data];
    XCTAssertEqualObjects([expected lowercaseString], actual);
}

- (void)testPublicKeyGeneration {
    NSString *Asn1PublicKey =
    @"-----BEGIN RSA PUBLIC KEY-----\n"
    @"MIIBCgKCAQEA61BjmfXGEvWmegnBGSuS+rU9soUg2FnODva32D1AqhwdziwHINFa\n"
    @"D1MVlcrYG6XRKfkcxnaXGfFDWHLEvNBSEVCgJjtHAGZIm5GL/KA86KDp/CwDFMSw\n"
    @"luowcXwDwoyinmeOY9eKyh6aY72xJh7noLBBq1N0bWi1e2i+83txOCg4yV2oVXhB\n"
    @"o8pYEJ8LT3el6Smxol3C1oFMVdwPgc0vTl25XucMcG/ALE/KNY6pqC2AQ6R2ERlV\n"
    @"gPiUWOPatVkt7+Bs3h5Ramxh7XjBOXeulmCpGSynXNcpZ/06+vofGi/2MlpQZNhH\n"
    @"Ao8eayMp6FcvNucIpUndo1X8dKMv3Y26ZQIDAQAB\n"
    @"-----END RSA PUBLIC KEY-----\n";
    JKBigInteger *n = [[JKBigInteger alloc] initWithString:@"eb506399f5c612f5a67a09c1192b92fab53db28520d859ce0ef6b7d83d40aa1c1dce2c0720d15a0f531595cad81ba5d129f91cc6769719f1435872c4bcd0521150a0263b470066489b918bfca03ce8a0e9fc2c0314c4b096ea30717c03c28ca29e678e63d78aca1e9a63bdb1261ee7a0b041ab53746d68b57b68bef37b71382838c95da8557841a3ca58109f0b4f77a5e929b1a25dc2d6814c55dc0f81cd2f4e5db95ee70c706fc02c4fca358ea9a82d8043a47611195580f89458e3dab5592defe06cde1e516a6c61ed78c13977ae9660a9192ca75cd72967fd3afafa1f1a2ff6325a5064d847028f1e6b2329e8572f36e708a549dda355fc74a32fdd8dba65" andRadix:16];
    JKBigInteger *e = [[JKBigInteger alloc] initWithString:@"10001" andRadix:16];
    NSArray *arr = [NSArray arrayWithObjects:n, e, nil];
    NSString *str = [X509Der derEncodeRsaKey:arr public:true];
    XCTAssertEqualObjects(str, Asn1PublicKey);
}

@end

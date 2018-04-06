//
//  Pbkdf2Rng_Test.m
//  Tests
//
//  Created by Admin Admin on 4/2/18.
//  Copyright © 2018 RNRSA. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "Pbkdf2Rng.h"

@interface Pbkdf2Rng_Test : XCTestCase

@end

@implementation Pbkdf2Rng_Test

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testRng {
    Pbkdf2Rng *rng = [[Pbkdf2Rng alloc] initWithSeed:@"test" andNumBits:2048];
    uint8_t *bytes = [rng nextBytes:12];
    NSData *data = [NSData dataWithBytes:bytes length:12];
    NSMutableString *sbuf = [NSMutableString stringWithCapacity:data.length*2];
    const uint8_t *buf = data.bytes;
    for (int i=0; i<data.length; i++) {
        [sbuf appendFormat:@"%02X", (unsigned int)buf[i]];
    }
    XCTAssertNotNil((id)data);
}

- (NSString *) getStringFromUint8:(uint8_t *)bytes bytesLength:(int)bytesLength {
    NSData *data = [NSData dataWithBytes:bytes length:bytesLength];
    NSMutableString *sbuf = [NSMutableString stringWithCapacity:data.length*2];
    const uint8_t *buf = data.bytes;
    for (int i=0; i<data.length; i++) {
        [sbuf appendFormat:@"%02x", (unsigned int)buf[i]];
    }
    return sbuf;
}

- (void)testWithSeed {
    uint8_t useed[6] = {0,1,2,3,4,5};
    NSData *seedData = [NSData dataWithBytes:useed length:6];
    NSString *seed = [[NSString alloc] initWithData:seedData encoding:NSISOLatin1StringEncoding];
    Pbkdf2Rng *rng = [[Pbkdf2Rng alloc] initWithSeed:seed andNumBits:16];
    uint8_t *bytes = [rng nextBytes:16];
    XCTAssertNotEqual((size_t)bytes, 0);
    NSString *bytesStr = [self getStringFromUint8:bytes bytesLength:16];
    XCTAssertEqualObjects(bytesStr, @"beb0e02c6daf239d04b993e564bcc019");
    for (int i=0; i<64; i++) {
        [rng nextBytes:16];
    }
    bytes = [rng nextBytes:16];
    bytesStr = [self getStringFromUint8:bytes bytesLength:16];
    XCTAssertEqualObjects(bytesStr, @"61e44b6137c5f45ee2923b88e370153c");
}

-(void)testDoubleLockstep {
    uint8_t useed[6] = {0xde,0xad,0xbe,0xef,0xde,0xad};
    int bits = 8;
    NSData *seedData = [NSData dataWithBytes:useed length:6];
    NSString *seed = [[NSString alloc] initWithData:seedData encoding:NSISOLatin1StringEncoding];
    Pbkdf2Rng *rng1 = [[Pbkdf2Rng alloc] initWithSeed:seed andNumBits:bits];
    Pbkdf2Rng *rng2 = [[Pbkdf2Rng alloc] initWithSeed:seed andNumBits:bits];
    for (int i=0; i<2; i++) {
        XCTAssertEqualObjects([self getStringFromUint8:[rng1 nextBytes:bits] bytesLength:bits],
                              [self getStringFromUint8:[rng2 nextBytes:bits] bytesLength:bits]);
    }
}

@end

//
//  RSADeterministic_Test.m
//  Tests
//
//  Created by Admin Admin on 4/3/18.
//  Copyright © 2018 RNRSA. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "RSADeterministic.h"

@interface RSADeterministic_Test : XCTestCase

@end

@implementation RSADeterministic_Test

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testDeterministicGeneration {
    uint8_t useed[6] = {0,1,2,3,4,5};
    NSData *seedData = [NSData dataWithBytes:useed length:6];
    NSString *seed = [[NSString alloc] initWithData:seedData encoding:NSISOLatin1StringEncoding];
    NSDictionary *key1 = [RSADeterministic generateDeterministic:512 eInt:0x10001 seed:seed];
    NSDictionary *key2 = [RSADeterministic generateDeterministic:512 eInt:0x10001 seed:seed];
    XCTAssert(key1 != NULL);
    XCTAssert(key2 != NULL);
    XCTAssertEqualObjects([key1 objectForKey:@"public"], [key2 objectForKey:@"public"]);
    XCTAssertEqualObjects([key1 objectForKey:@"private"], [key2 objectForKey:@"private"]);
}

- (void)testDeterministicGenerationAgainstConstant {
    NSString *expectedPublic = @"-----BEGIN RSA PUBLIC KEY-----\n"
    @"MIGJAoGBALcTxk8fHH2Gz5d26r9aTjPeqFiOqHfZJcqift1bhtGsBpZZndB8fafT\n"
    @"JjmbYPGqSp/eJhEMdBr01YpmXLRmAcX5bLRJJHkmLNw/dKLJFnp5Iiu9XzUuVtTV\n"
    @"sNjyrrbBaxkdN8z8E3tRJBwGcPGv3+PfBVXF7UoFrfqHTRDoFOiDAgMBAAE=\n"
    @"-----END RSA PUBLIC KEY-----\n";
    NSString *expectedPrivate = @"-----BEGIN RSA PRIVATE KEY-----\n"
    @"MIICXAIBAAKBgQC3E8ZPHxx9hs+Xduq/Wk4z3qhYjqh32SXKon7dW4bRrAaWWZ3Q\n"
    @"fH2n0yY5m2Dxqkqf3iYRDHQa9NWKZly0ZgHF+Wy0SSR5JizcP3SiyRZ6eSIrvV81\n"
    @"LlbU1bDY8q62wWsZHTfM/BN7USQcBnDxr9/j3wVVxe1KBa36h00Q6BTogwIDAQAB\n"
    @"AoGAGE6+VlQFpt8G4g/udDCr0HRAOt3aHWuN+n0fxgk4ec9S4pSMgRl+X5GH8j8g\n"
    @"nIWlOdu3hyz1n3yhe6pCpcsjcekC3loPM726a+3DP5WkPgXGntHm8DzqxOpZ4dwG\n"
    @"fzXc+rZuGRzr3qiSH5mRg6ZSsZSRPKBjjZtGknvJ1m2QsR0CQQC4QdXFVITk5G9L\n"
    @"pca3Obx+SWWUhIfGAvRnQWpQ3AJ2JdODSKdSn7YrrmTS38yrsxmFmsW1SPSPhKCB\n"
    @"BnzIFu6PAkEA/lxUH9N9i+cKQcBu+5xo9HVYevkfiGU9UnoxmkQrzZT0TRvdVO2v\n"
    @"ZE7NaHYOjwsBEC4Vc9s3pjMRQfl9xLogzQJBAKTFStMx572Agf5V+sPy/5q3K/2K\n"
    @"Hph2H/UOTHKOrCzXWrQ2DlsWs6OQSl1BARgyCwqtA0xAN2L4KUf4czHDQAUCQEDx\n"
    @"l/UMTajT07WYCX4qoE2STIYRZ3Cu0KpnUpTdxQVXe8zYSXmuujJ1QFLkmbECEUJt\n"
    @"UcLj/OBtd4GNzwPUth0CQAZW4fbjVfvpn4RFycSWPcw4GIw9jdZ+zp1ztb9Cmvgt\n"
    @"sRiVP+uUp7tg23ahA36Oghe9HeqenxjI5EytVGfV9VI=\n"
    @"-----END RSA PRIVATE KEY-----\n";

    uint8_t useed[6] = {0,1,2,3,4,5};
    NSData *seedData = [NSData dataWithBytes:useed length:6];
    NSString *seed = [[NSString alloc] initWithData:seedData encoding:NSISOLatin1StringEncoding];
    NSDictionary *key = [RSADeterministic generateDeterministic:1024 eInt:0x10001 seed:seed];
    XCTAssert(key != NULL);
    XCTAssertEqualObjects([key objectForKey:@"public"], expectedPublic);
    XCTAssertEqualObjects([key objectForKey:@"private"], expectedPrivate);
}


@end

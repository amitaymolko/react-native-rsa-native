#import <XCTest/XCTest.h>
#import "RSANative.h"

@interface RNRSA_Test : XCTestCase

@end

@implementation RNRSA_Test

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testRSAGenerate {
    RSANative *rsa = [[RSANative alloc] init];
    [rsa generate];
    XCTAssertNotNil([rsa encodedPublicKey]);
    XCTAssertEqualObjects([rsa decrypt:[rsa encrypt:@"test"]], @"test");
}



- (void)testKeyTagStorage {
    NSString *keyTag = @"com.sample.rnrsa";
    RSANative *rsa = [[RSANative alloc] initWithKeyTag:keyTag];
    [rsa generate];
    rsa = [[RSANative alloc] initWithKeyTag:keyTag];
    XCTAssertNotNil([rsa encodedPublicKey]);
    XCTAssertEqualObjects([rsa decrypt:[rsa encrypt:@"test"]], @"test");
}

- (void)testKeyTagStorageWithSetting {
    NSString *public = @"-----BEGIN RSA PUBLIC KEY-----\n"
    @"MIGJAoGBALcTxk8fHH2Gz5d26r9aTjPeqFiOqHfZJcqift1bhtGsBpZZndB8fafT\n"
    @"JjmbYPGqSp/eJhEMdBr01YpmXLRmAcX5bLRJJHkmLNw/dKLJFnp5Iiu9XzUuVtTV\n"
    @"sNjyrrbBaxkdN8z8E3tRJBwGcPGv3+PfBVXF7UoFrfqHTRDoFOiDAgMBAAE=\n"
    @"-----END RSA PUBLIC KEY-----\n";
    NSString *private = @"-----BEGIN RSA PRIVATE KEY-----\n"
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

    NSString *keyTag = @"com.sample.rnrsa";
    NSDictionary *keys = @{@"public":public, @"private": private};

    RSANative *rsa = [[RSANative alloc] initWithKeyTag:keyTag];
    [rsa addKeysToKeychain:keys];

    // Verify that we can use the keys we just created
    XCTAssertEqualObjects([rsa decrypt:[rsa encrypt:@"test"]], @"test");

    // Reinit the rsa library. Keys should be stored in the keychain and thus fetchable
    rsa = [[RSANative alloc] initWithKeyTag:keyTag];
    NSString *receivedPublic = [rsa encodedPublicKey];
    NSString *receivedPrivate = [rsa encodedPrivateKey];
    XCTAssertEqualObjects(public, receivedPublic);
    XCTAssertEqualObjects(private, receivedPrivate);
    XCTAssertEqualObjects([rsa decrypt:[rsa encrypt:@"test"]], @"test");
}

@end

#import "RNRSA.h"
#import "RSANative.h"

@implementation RNRSA

- (dispatch_queue_t)methodQueue {
    return dispatch_get_main_queue();
}

RCT_EXPORT_MODULE()

- (NSDictionary *)constantsToExport
{
    return @{
             @"SHA256withRSA": @"SHA256withRSA",
             @"SHA512withRSA": @"SHA512withRSA"
             };
}
// Key based API, provide the public or private key with each call - pending discussions with @amitaymolko

RCT_EXPORT_METHOD(generate:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    [self generateKeys:2048 resolve:resolve rejecter:reject];
}

RCT_EXPORT_METHOD(generateKeys:(int)keySize resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        RSANative *rsa = [[RSANative alloc] init];
        [rsa generate:keySize withDigest: @"Digest_SHA512"];
        NSDictionary *keys = @{
                            @"private" : [rsa encodedPrivateKey],
                            @"public" : [rsa encodedPublicKey]
                            };
        resolve(keys);
    });
}

RCT_EXPORT_METHOD(encrypt:(NSString *)message withKey:(NSString *)key resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        RSANative *rsa = [[RSANative alloc] init];
        rsa.publicKey = key;
        NSString *encodedMessage = [rsa encrypt:message];
        resolve(encodedMessage);
    });
}

RCT_EXPORT_METHOD(decrypt:(NSString *)encodedMessage withKey:(NSString *)key resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        RSANative *rsa = [[RSANative alloc] init];
        rsa.privateKey = key;
        NSString *message = [rsa decrypt:encodedMessage];
        resolve(message);
    });
}

RCT_EXPORT_METHOD(encrypt64:(NSString *)message withKey:(NSString *)key resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        RSANative *rsa = [[RSANative alloc] init];
        rsa.publicKey = key;
        NSString *encodedMessage = [rsa encrypt64:message];
        resolve(encodedMessage);
    });
}

RCT_EXPORT_METHOD(decrypt64:(NSString *)encodedMessage withKey:(NSString *)key resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        RSANative *rsa = [[RSANative alloc] init];
        rsa.privateKey = key;
        NSString *message = [rsa decrypt64:encodedMessage];
        resolve(message);
    });
}


RCT_EXPORT_METHOD(sign:(NSString *)message withKey:(NSString *)key resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        RSANative *rsa = [[RSANative alloc] init];
        rsa.privateKey = key;
        NSString *signature = [rsa sign:message withAlgorithm: @"SHA512withRSA"];
        resolve(signature);
    });
}

RCT_EXPORT_METHOD(sign64:(NSString *)message withKey:(NSString *)key resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        RSANative *rsa = [[RSANative alloc] init];
        rsa.privateKey = key;
        NSString *signature = [rsa sign64:message];
        resolve(signature);
    });
}

RCT_EXPORT_METHOD(verify:(NSString *)signature withMessage:(NSString *)message andKey:(NSString *)key resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        RSANative *rsa = [[RSANative alloc] init];
        rsa.publicKey = key;
        BOOL valid = [rsa verify:signature withMessage:message];
        resolve(@(valid));
    });
}

RCT_EXPORT_METHOD(verify64:(NSString *)signature withMessage:(NSString *)message andKey:(NSString *)key resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        RSANative *rsa = [[RSANative alloc] init];
        rsa.publicKey = key;
        BOOL valid = [rsa verify64:signature withMessage:message];
        resolve(@(valid));
    });
}

@end

@implementation RNRSAKeychain

- (dispatch_queue_t)methodQueue {
    return dispatch_get_main_queue();
}

RCT_EXPORT_MODULE()

- (NSDictionary *)constantsToExport
{
    return @{
             @"SHA256withRSA": @"SHA256withRSA",
             @"SHA512withRSA": @"SHA512withRSA",
             @"Digest_SHA256": @"SHA-256",
             @"Digest_SHA512": @"SHA-512"
            };
}
// Keychain based API, provide a key chain tag with each call

RCT_EXPORT_METHOD(generateWithDigest:(NSString *)keyTag digest:(NSString *)digest resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        RSANative *rsa = [[RSANative alloc] initWithKeyTag:keyTag];
        [rsa generate:2048 withDigest: digest];
        NSDictionary *keys = @{@"public" : [rsa encodedPublicKey]};
        resolve(keys);
    });
}

RCT_EXPORT_METHOD(generate:(NSString *)keyTag resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    [self generateKeys:keyTag keySize:2048 resolve:resolve rejecter:reject];
}

RCT_EXPORT_METHOD(generateKeys:(NSString *)keyTag keySize:(int)keySize resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        RSANative *rsa = [[RSANative alloc] initWithKeyTag:keyTag];
        [rsa generate:keySize withDigest: @"Digest_SHA512"];
        NSDictionary *keys = @{@"public" : [rsa encodedPublicKey]};
        resolve(keys);
    });
}

RCT_EXPORT_METHOD(deletePrivateKey:(NSString *)keyTag resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    RSANative *rsa = [[RSANative alloc] initWithKeyTag:keyTag];
    [rsa deletePrivateKey];
    resolve(@(YES));
}

RCT_EXPORT_METHOD(encrypt:(NSString *)message withKeyTag:(NSString *)keyTag resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        RSANative *rsa = [[RSANative alloc] initWithKeyTag:keyTag];
        NSString *encodedMessage = [rsa encrypt:message];
        resolve(encodedMessage);
    });
}

RCT_EXPORT_METHOD(decrypt:(NSString *)encodedMessage withKeyTag:(NSString *)keyTag resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        RSANative *rsa = [[RSANative alloc] initWithKeyTag:keyTag];
        NSString *message = [rsa decrypt:encodedMessage];
        resolve(message);
    });
}

RCT_EXPORT_METHOD(signWithAlgorithm:(NSString *)message withKeyTag:(NSString *)keyTag withAlgorithm:(NSString *)algorithm resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        RSANative *rsa = [[RSANative alloc] initWithKeyTag:keyTag];
        NSString *signature = [rsa sign:message withAlgorithm: algorithm];
        resolve(signature);
    });
}

RCT_EXPORT_METHOD(sign:(NSString *)message withKeyTag:(NSString *)keyTag resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        RSANative *rsa = [[RSANative alloc] initWithKeyTag:keyTag];
        NSString *signature = [rsa sign:message withAlgorithm: @"SHA512withRSA"];
        resolve(signature);
    });
}

RCT_EXPORT_METHOD(verify:(NSString *)signature withMessage:(NSString *)message andKeyTag:(NSString *)keyTag resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        RSANative *rsa = [[RSANative alloc] initWithKeyTag:keyTag];
        BOOL valid = [rsa verify:signature withMessage:message];
        resolve(@(valid));
    });
}

RCT_EXPORT_METHOD(getPublicKey:(NSString *)keyTag resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    RSANative *rsa = [[RSANative alloc] initWithKeyTag:keyTag];
    NSString *key = [rsa encodedPublicKey];
    resolve(key);
}

@end

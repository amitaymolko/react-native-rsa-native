#import "RNRSA.h"
#import "RSANative.h"

@implementation RNRSA

- (dispatch_queue_t)methodQueue
{
    return dispatch_get_main_queue();
}
RCT_EXPORT_MODULE()


RCT_EXPORT_METHOD(generate:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    RSANative *rsa = [[RSANative alloc] init];
    [rsa generate];
    NSDictionary *keys = @{
                           @"private" : [rsa getPrivateKey],
                           @"public" : [rsa getPublicKey]
                           };
    
    NSLog(@"public key %@", keys[@"public"]);
    NSLog(@"private key %@", keys[@"private"]);
    
    resolve(keys);
}

RCT_EXPORT_METHOD(encrypt:(NSString *) message withKey:(NSString *) key resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    RSANative *rsa = [[RSANative alloc] init];
    [rsa setPublicKey:key];
    NSString *encodedMessage = [rsa encrypt:message];
    resolve(encodedMessage);
}

RCT_EXPORT_METHOD(decrypt:(NSString *) encodedMessage withKey:(NSString *) key resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    RSANative *rsa = [[RSANative alloc] init];
    [rsa setPrivateKey:key];
    NSString *message = [rsa decrypt:encodedMessage];
    resolve(message);
}
@end
  

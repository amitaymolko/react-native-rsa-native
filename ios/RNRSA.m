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
    RSANative *rsa = [RSANative new];
    [rsa generate];
    NSDictionary *keys = @{
                           @"private" : [rsa getPrivateKey],
                           @"public" : [rsa getPublicKey]
                           };
    resolve(keys);
}

@end
  

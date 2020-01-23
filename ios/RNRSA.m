
//
//  RNECRSASwift.m
//  RNECRSA
//
//  Created by saeed kargosha .
//  Copyright © 1398 saeed kargosha. All rights reserved.
//

#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(RNRSA, NSObject)

RCT_EXTERN_METHOD(generate:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(generateKeys:(int)keySize resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)


RCT_EXTERN_METHOD(sign:(NSString *)message withKey:(NSString *)withKey resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)


RCT_EXTERN_METHOD(signWithAlgorithm:(NSString *)message withKey:(NSString *)withKey withAlgorithm:(NSString *)withAlgorithm resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(sign64:(NSString *)message withKey:(NSString *)withKey resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(sign64WithAlgorithm:(NSString *)message withKey:(NSString *)withKey withAlgorithm:(NSString *)withAlgorithm resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)


RCT_EXTERN_METHOD(verify:(NSString *)signature withMessage:(NSString *)withMessage withKey:(NSString *)withKey resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(verifyWithAlgorithm:(NSString *)signature withMessage:(NSString *)withMessage withKey:(NSString *)withKey withAlgorithm:(NSString *)withAlgorithm resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)


RCT_EXTERN_METHOD(verify64:(NSString *)signature withMessage:(NSString *)withMessage withKey:(NSString *)withKey resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(verify64WithAlgorithm:(NSString *)signature withMessage:(NSString *)withMessage withKey:(NSString *)withKey withAlgorithm:(NSString *)withAlgorithm resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)


RCT_EXTERN_METHOD(decrypt:(NSString *)message withKey:(NSString *)withKey resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(encrypt:(NSString *)message withKey:(NSString *)withKey resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(decrypt64:(NSString *)message withKey:(NSString *)withKey resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(encrypt64:(NSString *)message withKey:(NSString *)withKey resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)


@end








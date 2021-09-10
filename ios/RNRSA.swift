//
//  RNRSASwift.swift
//  test
//

//#if canImport(React)
//import React
//#endif
import Foundation

@objc(RNRSA)
class RNRSA: NSObject {
    

    @objc
    static
    func requiresMainQueueSetup() -> Bool {
      return false
    }

    @objc
    func constantsToExport() -> [AnyHashable : Any]! {
        return[
            "SHA256withRSA": "SHA256withRSA",
            "SHA512withRSA": "SHA512withRSA",
            "SHA1withRSA"  : "SHA1withRSA",
            "SHA256withECDSA" : "SHA256withECDSA",
            "SHA512withECDSA" : "SHA512withECDSA",
            "SHA1withECDSA"   : "SHA1withECDSA"
        ]
    }
    
    
    
    // generate key with default keysize - RSA - DER format
    @objc
    func generate(_ resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        self.generateKeys(2048, resolver: resolve, rejecter: reject)
    }
    
    // generate key with keysize - RSA - DER format
    @objc
    func generateKeys(_ keySize: Int, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative()
        let res = rsa_ec.generate(keySize: keySize)
        if(res ?? false){
            let pub = rsa_ec.encodedPublicKeyDER()
            let prv = rsa_ec.encodedPrivateKeyRSA()
            let keys = ["public": pub, "private": prv]
            resolve(keys)
            return
        }
        resolve(false)
    }
    
    @objc
    func encrypt(_ message: String ,withKey: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative()
        guard let _ = rsa_ec.setPublicKey(publicKey: withKey) else {
            resolve(false)
            return
        }
        let msg = rsa_ec.encrypt(message: message)
        resolve(msg)
    }
    
    @objc
    func decrypt(_ message: String ,withKey: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative()
        guard let _ = rsa_ec.setPrivateKey(privateKey: withKey) else {
            resolve(false)
            return
        }
        let msg = rsa_ec.decrypt(message: message)
        resolve(msg)
    }
    
    
    @objc
    func encrypt64(_ message: String ,withKey: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative()
        guard let _ = rsa_ec.setPublicKey(publicKey: withKey) else {
            resolve(false)
            return
        }
        let msg = rsa_ec.encrypt64(message: message)
        resolve(msg)
    }
    
    @objc
    func decrypt64(_ message: String ,withKey: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative()
        guard let _ = rsa_ec.setPrivateKey(privateKey: withKey) else {
            resolve(false)
            return
        }
        let msg = rsa_ec.decrypt64(message: message)
        resolve(msg)
    }
    
    @objc
    func verify(_ signature: String, withMessage: String ,withKey: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative()
        guard let _ = rsa_ec.setPublicKey(publicKey: withKey) else {
            resolve(false)
            return
        }
        let verifyResult = rsa_ec.verify(encodedSignature: signature, withMessage: withMessage, withAlgorithm: "SHA512withRSA")
        if(verifyResult == false){
            reject("verify failed", "error", nil)
        }else {
            resolve(true)
        }
    }
    
    @objc
    func verifyWithAlgorithm(_ signature: String, withMessage: String ,withKey: String, withAlgorithm: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative()
        guard let _ = rsa_ec.setPublicKey(publicKey: withKey) else {
            print("public key set failed")
            resolve(false)
            return
        }
        let verifyResult = rsa_ec.verify(encodedSignature: signature, withMessage: withMessage, withAlgorithm: withAlgorithm)
        if(verifyResult == false){
            print("verify failed")
            reject("verify failed", "error", nil)
        }else {
            resolve(true)
        }
    }
    
    
    @objc
    func verify64(_ signature: String, withMessage: String ,withKey: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative()
        guard let _ = rsa_ec.setPublicKey(publicKey: withKey) else {
            resolve(false)
            return
        }
        let verifyResult = rsa_ec.verify64(encodedSignature: signature, withMessage: withMessage, withAlgorithm: "SHA512withRSA")
        if(verifyResult == false){
            reject("verify failed", "error", nil)
        }else {
            resolve(true)
        }
    }
    
    @objc
    func verify64WithAlgorithm(_ signature: String, withMessage: String ,withKey: String, withAlgorithm: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative()
        guard let _ = rsa_ec.setPublicKey(publicKey: withKey) else {
            resolve(false)
            return
        }
        let verifyResult = rsa_ec.verify64(encodedSignature: signature, withMessage: withMessage, withAlgorithm: withAlgorithm)
        if(verifyResult == false){
            reject("verify failed", "error", nil)
        }else {
            resolve(true)
        }
    }
    
    
    @objc
    func sign(_ message: String, withKey: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative()
        guard let _ = rsa_ec.setPrivateKey(privateKey: withKey) else {
            resolve(false)
            return
        }
        let signature = rsa_ec.sign(message: message, withAlgorithm: "SHA512withRSA", withEncodeOption: NSData.Base64EncodingOptions(rawValue: 0))
        if(signature == nil){
            reject("not sign it", "error", nil)
        }else {
            resolve(signature)
        }
    }
    
    @objc
    func signWithAlgorithm(_ message: String, withKey: String, withAlgorithm: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative()
        guard let _ = rsa_ec.setPrivateKey(privateKey: withKey) else {
            resolve(false)
            return
        }
        let signature = rsa_ec.sign(message: message, withAlgorithm: withAlgorithm, withEncodeOption: NSData.Base64EncodingOptions(rawValue: 0))
        if(signature == nil){
            reject("not sign it", "error", nil)
        }else {
            resolve(signature)
        }
    }
    
    @objc
    func sign64(_ message: String, withKey: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative()
        guard let _ = rsa_ec.setPrivateKey(privateKey: withKey) else {
            resolve(false)
            return
        }
        let signature = rsa_ec.sign64(b64message: message, withAlgorithm: "SHA512withRSA")
        if(signature == nil){
            reject("not sign it", "error", nil)
        }else {
            resolve(signature)
        }
    }
    
    @objc
    func sign64WithAlgorithm(_ message: String, withKey: String, withAlgorithm: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative()
        guard let _ = rsa_ec.setPrivateKey(privateKey: withKey) else {
            resolve(false)
            return
        }
        let signature = rsa_ec.sign64(b64message: message, withAlgorithm: withAlgorithm)
        if(signature == nil){
            reject("not sign it", "error", nil)
        }else {
            resolve(signature)
        }
    }
    
}











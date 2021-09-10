//
//  RNRSASwift.swift
//  test
//

//#if canImport(React)
//import React
//#endif
import Foundation

@objc(RNRSAKeychain)
class RNRSAKeychain: NSObject {

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
    func generate(_ keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        // with default alogo RSA
        let res = rsa_ec.generate(keySize: 2048)
        if(res ?? false){
            let pub = rsa_ec.encodedPublicKeyDER()
            let keys = ["public": pub]
            resolve(keys)
            return
        }
        resolve(false)
        
    }
    
    // generate key with keysize - RSA - DER format
    @objc
    func generateKeys(_ keyTag: String, keySize: Int, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        // with default alogo RSA
        let res = rsa_ec.generate(keySize: keySize)
        if(res ?? false){
            let pub = rsa_ec.encodedPublicKeyDER()
            let keys = ["public": pub]
            resolve(keys)
            return
        }
        resolve(false)
    }
    
    @objc
    func generateCSR(_ keyTag: String, CN: String, withAlgorithm: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let csr = rsa_ec.generateCSR(CN: CN, withAlgorithm: withAlgorithm)
        if(csr != nil){
            let keys = ["csr": csr]
            resolve(keys)
        }else {
            reject("not exist CSR", "error", nil)
        }
    }
    
    @objc
    func generateCSRWithEC(_ CN: String, keyTag: String, keySize: Int, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let res = rsa_ec.generateEC()
        let pub = rsa_ec.encodedPublicKey()
        let csr = rsa_ec.generateCSR(CN: CN, withAlgorithm: "SHA256withECDSA")
        if(csr != nil){
            let keys = ["csr": csr, "public": pub]
            resolve(keys)
        }else {
            reject("not exist CSR", "error", nil)
        }
    }
    
    @objc
    func generateEC(_ keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let res = rsa_ec.generateEC()
        if(res ?? false){
            let pub = rsa_ec.encodedPublicKey()
            let keys = ["public": pub]
            resolve(keys)
            return
        }
        resolve(false)
    }
    
    @objc
    func sign(_ message: String, keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let signature = rsa_ec.sign(message: message, withAlgorithm: "SHA512withRSA", withEncodeOption: NSData.Base64EncodingOptions(rawValue: 0))
        if(signature == nil){
            reject("not sign it", "error", nil)
        }else {
            resolve(signature)
        }
    }
    
    @objc
    func signWithAlgorithm(_ message: String, keyTag: String, withAlgorithm: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let signature = rsa_ec.sign(message: message, withAlgorithm: withAlgorithm, withEncodeOption: NSData.Base64EncodingOptions(rawValue: 0))
        if(signature == nil){
            reject("not sign it", "error", nil)
        }else {
            resolve(signature)
        }
    }
    
    @objc
    func sign64(_ message: String, keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let signature = rsa_ec.sign64(b64message: message, withAlgorithm: "SHA512withRSA")
        if(signature == nil){
            reject("not sign it", "error", nil)
        }else {
            resolve(signature)
        }
    }
    
    @objc
    func sign64WithAlgorithm(_ message: String, keyTag: String, withAlgorithm: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let signature = rsa_ec.sign64(b64message: message, withAlgorithm: withAlgorithm)
        if(signature == nil){
            reject("not sign it", "error", nil)
        }else {
            resolve(signature)
        }
    }
    
    // generate key with default keysize  - DER format
    @objc
    func getPublicKeyDER(_ keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let pub = rsa_ec.encodedPublicKeyDER()
        if(pub == nil){
            reject("not exist public key", "error", nil)
        }else {
            let keys = ["public": pub]
            resolve(keys)
        }
    }
    
    // generate key with default keysize  - DER format
    @objc
    func getPublicKey(_ keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let pub = rsa_ec.encodedPublicKey()
        if(pub == nil){
            reject("not exist public key", "error", nil)
        }else {
            let keys = ["public": pub]
            resolve(keys)
        }
    }
    
    // generate key with default keysize  - DER format
    @objc
    func getPublicKeyRSA(_ keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let pub = rsa_ec.encodedPublicKeyRSA()
        if(pub == nil){
            reject("not exist public key", "error", nil)
        }else {
            let keys = ["public": pub]
            resolve(keys)
        }
    }
    
    @objc
    func verify(_ signature: String, withMessage: String, keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let verifyResult = rsa_ec.verify(encodedSignature: signature, withMessage: withMessage, withAlgorithm: "SHA512withRSA")
        if(verifyResult == false){
            reject("verify failed", "error", nil)
        }else {
            resolve(true)
        }
    }
    
    @objc
    func verifyWithAlgorithm(_ signature: String, withMessage: String ,keyTag: String, withAlgorithm: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let verifyResult = rsa_ec.verify(encodedSignature: signature, withMessage: withMessage, withAlgorithm: withAlgorithm)
        if(verifyResult == false){
            reject("verify failed", "error", nil)
        }else {
            resolve(true)
        }
    }
    
    @objc
    func verify64(_ signature: String, withMessage: String ,keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let verifyResult = rsa_ec.verify64(encodedSignature: signature, withMessage: withMessage, withAlgorithm: "SHA512withRSA")
        if(verifyResult == false){
            reject("verify failed", "error", nil)
        }else {
            resolve(true)
        }
    }
    
    @objc
    func verify64WithAlgorithm(_ signature: String, withMessage: String ,keyTag: String, withAlgorithm: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let verifyResult = rsa_ec.verify64(encodedSignature: signature, withMessage: withMessage, withAlgorithm: withAlgorithm)
        if(verifyResult == false){
            reject("verify failed", "error", nil)
        }else {
            resolve(true)
        }
    }
    
    @objc
    func deletePrivateKey(_ keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        rsa_ec.deletePrivateKey()
        resolve(true)
    }
    
    
    @objc
    func decrypt(_ message: String ,keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let msg = rsa_ec.decrypt(message: message)
        resolve(msg)
    }
    
    @objc
    func encrypt(_ message: String ,keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let msg = rsa_ec.encrypt(message: message)
        resolve(msg)
    }
    
    @objc
    func decrypt64(_ message: String ,keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let msg = rsa_ec.decrypt64(message: message)
        resolve(msg)
    }
    
    @objc
    func encrypt64(_ message: String ,keyTag: String, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let rsa_ec = RSAECNative(keyTag: keyTag)
        let msg = rsa_ec.encrypt64(message: message)
        resolve(msg)
    }
    
}


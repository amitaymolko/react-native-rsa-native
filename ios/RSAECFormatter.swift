//
//  RSAECFormatter.swift
//  BVLinearGradient
//
//  Created by saeed kargosha.
//

import Foundation

class RSAECFormatter: NSObject {
    
    static let publicTag = "PUBLIC"
    static let privateTag = "PRIVATE"
    static let publicRsaTag = "RSA PUBLIC"
    static let privateRsaTag = "RSA PRIVATE"
    
    static public func PEMFormattedPublicKeyRSA(publicKeyData: Data) -> String {
        var encodedKey = Data()
        encodedKey.append(publicKeyData)
        return self.pemFormat(encodedKey: encodedKey, tag: publicRsaTag)
    }
    
    static public func PEMFormattedPrivateKeyRSA(privateKeyData: Data) -> String {
        var encodedKey = Data()
        encodedKey.append(privateKeyData)
        return self.pemFormat(encodedKey: encodedKey, tag: privateRsaTag)
    }
    
    static public func PEMFormattedPublicKey(publicKeyData: Data) -> String {
        var encodedKey = Data()
        encodedKey.append(publicKeyData)
        return self.pemFormat(encodedKey: encodedKey, tag: publicTag)
    }
    
    static public func PEMFormattedPrivateKey(privateKeyData: Data) -> String {
        var encodedKey = Data()
        encodedKey.append(privateKeyData)
        return self.pemFormat(encodedKey: encodedKey, tag: privateTag)
    }
    
    static public func pemFormat(encodedKey: Data, tag: String) -> String {
        
        return String(format: "%@\n%@\n%@",
                      self.headerForTag(tag: tag),
                      encodedKey.base64EncodedString(options: NSData.Base64EncodingOptions(rawValue: 0)),
                      self.footerForTag(tag: tag))
    }
    
    
    static public func headerForTag(tag: String) -> String{
        return String(format: "-----BEGIN %@ KEY-----", tag)
    }
    
    static public func footerForTag(tag: String) -> String {
        return String(format: "-----END %@ KEY-----", tag)
    }
    
    static public func stripHeaders(pemString: String) -> String? {
        var str: String? = nil
        if(pemString.contains(RSAECFormatter.headerForTag(tag: RSAECFormatter.privateRsaTag))){
            str = pemString.replacingOccurrences(of: RSAECFormatter.headerForTag(tag: RSAECFormatter.privateRsaTag), with: "")
            str = str!.replacingOccurrences(of: RSAECFormatter.footerForTag(tag: RSAECFormatter.privateRsaTag), with: "")
        }else if(pemString.contains(RSAECFormatter.headerForTag(tag: RSAECFormatter.privateTag))){
            str = pemString.replacingOccurrences(of: RSAECFormatter.headerForTag(tag: RSAECFormatter.privateTag), with: "")
            str = str!.replacingOccurrences(of: RSAECFormatter.footerForTag(tag: RSAECFormatter.privateTag), with: "")
        }else if(pemString.contains(RSAECFormatter.headerForTag(tag: RSAECFormatter.publicRsaTag))){
            str = pemString.replacingOccurrences(of: RSAECFormatter.headerForTag(tag: RSAECFormatter.publicRsaTag), with: "")
            str = str!.replacingOccurrences(of: RSAECFormatter.footerForTag(tag: RSAECFormatter.publicRsaTag), with: "")
        }else if(pemString.contains(RSAECFormatter.headerForTag(tag: RSAECFormatter.publicTag))){
            str = pemString.replacingOccurrences(of: RSAECFormatter.headerForTag(tag: RSAECFormatter.publicTag), with: "")
            str = str!.replacingOccurrences(of: RSAECFormatter.footerForTag(tag: RSAECFormatter.publicTag), with: "")
        }
        return str
    }
    
}

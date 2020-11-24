//
//  CertificateSigningRequest.swift
//  CertificateSigningRequestSwift
//
//  Created by Corey Baker on 10/19/16.
//  Copyright © Corey Baker. All rights reserved.
//
//  This is a port of ios-csr by Ales Teska (https://github.com/ateska/ios-csr)
//  from Objective-c to Swift. Additions have been made to allow SHA256 and SHA512.
//
//  Copyright (C) 2016  Corey Baker
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.

//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.

/*
 
 Certification Request Syntax Specification: http://www.ietf.org/rfc/rfc2986.txt
 
 */

import Foundation
import CommonCrypto

public class CertificateSigningRequest:NSObject {
    private let OBJECT_commonName:[UInt8] = [0x06, 0x03, 0x55, 0x04, 0x03]
    private let OBJECT_countryName:[UInt8] = [0x06, 0x03, 0x55, 0x04, 0x06]
    private let OBJECT_localityName:[UInt8] = [0x06, 0x03, 0x55, 0x04, 0x07]
    private let OBJECT_organizationName:[UInt8] = [0x06, 0x03, 0x55, 0x04, 0x0A]
    private let OBJECT_organizationalUnitName:[UInt8] = [0x06, 0x03, 0x55, 0x04, 0x0B]
    private let OBJECT_stateOrProvinceName:[UInt8] = [0x06, 0x03, 0x55, 0x04, 0x08]
    private let SEQUENCE_tag:UInt8 = 0x30
    private let SET_tag:UInt8 = 0x31
    
    private let commonName:String?
    private let countryName:String?
    private let localityName:String?
    private let organizationName:String?
    private let organizationUnitName:String?
    private let stateOrProvinceName:String?
    private var keyAlgorithm: KeyAlgorithm!
    private var subjectDER:Data?
    
    
    public init(commonName: String?, organizationName:String?, organizationUnitName:String?, countryName:String?, stateOrProvinceName:String?, localityName:String?, keyAlgorithm: KeyAlgorithm){
        
        self.commonName = commonName
        self.organizationName = organizationName
        self.organizationUnitName = organizationUnitName
        self.countryName = countryName
        self.stateOrProvinceName = stateOrProvinceName
        self.localityName = localityName
        self.subjectDER = nil
        self.keyAlgorithm = keyAlgorithm
        
        super.init()
    }
    
    public convenience override init(){
        self.init(commonName: nil, organizationName:nil, organizationUnitName:nil, countryName:nil, stateOrProvinceName:nil, localityName:nil, keyAlgorithm: KeyAlgorithm.rsa(signatureType: .sha512))
    }
    
    public convenience init(keyAlgorithm: KeyAlgorithm){
        self.init(commonName: nil, organizationName:nil, organizationUnitName:nil, countryName:nil, stateOrProvinceName:nil, localityName:nil, keyAlgorithm: keyAlgorithm)
    }
    
    public func build(_ publicKeyBits:Data, privateKey: SecKey) -> Data?{
        
        var certificationRequestInfo = buldCertificationRequestInfo(publicKeyBits)
        var certificationRequestInfoBytes = [UInt8](repeating: 0, count: certificationRequestInfo.count)
        certificationRequestInfo.copyBytes(to: &certificationRequestInfoBytes, count: certificationRequestInfo.count)
        let shaBytes = keyAlgorithm.sequenceObjectEncryptionType
        
        // Allocate enough space for RSA-8192
        var signature = Data(capacity: 1024);
        
        if #available(iOS 11, *) {
            // Build signature - step 1: SHA1 hash
            // Build signature - step 2: Sign hash
            var error: Unmanaged<CFError>?
            
            if let signatureData = SecKeyCreateSignature(privateKey, keyAlgorithm.signatureAlgorithm, certificationRequestInfo as CFData, &error) as Data?{
                signature.append(signatureData)
            }
            
            if error != nil{
                print("Error in creating signature: \(error!.takeRetainedValue())")
            }
            
        } else {
            // Fallback on earlier versions
            
            // Build signature - step 1: SHA1 hash
            var digest = [UInt8](repeating: 0, count: keyAlgorithm.digestLength)
            let padding = keyAlgorithm.padding
            
            switch keyAlgorithm! {
                
            case .rsa(signatureType: .sha1), .ec(signatureType: .sha1):
                
                var SHA1 = CC_SHA1_CTX()
                CC_SHA1_Init(&SHA1)
                CC_SHA1_Update(&SHA1, certificationRequestInfoBytes, CC_LONG(certificationRequestInfo.count))
                
                CC_SHA1_Final(&digest, &SHA1)
                
            case .rsa(signatureType: .sha256), .ec(signatureType: .sha256):
                
                var SHA256 = CC_SHA256_CTX()
                CC_SHA256_Init(&SHA256)
                CC_SHA256_Update(&SHA256, certificationRequestInfoBytes, CC_LONG(certificationRequestInfo.count))
                CC_SHA256_Final(&digest, &SHA256)
                
            case .rsa(signatureType: .sha512), .ec(signatureType: .sha512):
                
                var SHA512 = CC_SHA512_CTX()
                CC_SHA512_Init(&SHA512)
                CC_SHA512_Update(&SHA512, certificationRequestInfoBytes, CC_LONG(certificationRequestInfo.count))
                CC_SHA512_Final(&digest, &SHA512)
                
                /*
                 default:
                 
                 print("Error: signing algotirthm \(signAlgorithm) is not implemented")
                 return nil
                 */
            }
            
            // Build signature - step 2: Sign hash
            var signatureRaw = [UInt8](repeating: 0, count: 1024);
            var signatureRawLen = 1024;
            let result = SecKeyRawSign(privateKey, padding, digest, digest.count, &signatureRaw, &signatureRawLen)
            signature.append(signatureRaw, count: signatureRawLen)
            
            if result != errSecSuccess{
                print("Error signing: \(result)")
                return nil
            }
            
        }
        
        
        var certificationRequest = Data(capacity: 1024)
        certificationRequest.append(certificationRequestInfo)
        certificationRequest.append(shaBytes, count: shaBytes.count)
        
        var signData = Data(capacity: 257)
        let zero:UInt8 = 0 // Prepend zero
        signData.append(zero)
        signData.append(signature)
        appendBITSTRING(signData, into: &certificationRequest)
        
        enclose(&certificationRequest, by: SEQUENCE_tag) // Enclose into SEQUENCE
        
        return certificationRequest
    }
    
    public func buildAndEncodeDataAsString(_ publicKeyBits:Data, privateKey: SecKey)-> String? {
        
        guard let buildData = self.build(publicKeyBits, privateKey: privateKey) else{
            return nil
        }
        
        return buildData.base64EncodedString(options: NSData.Base64EncodingOptions(rawValue: 0)).addingPercentEncoding(withAllowedCharacters: CharacterSet.urlQueryAllowed)
        
    }
    
    public func buildCSRAndReturnString(_ publicKeyBits:Data, privateKey: SecKey)-> String? {
        
        guard let csrString = self.buildAndEncodeDataAsString(publicKeyBits, privateKey: privateKey) else{
            return nil
        }
        
        let head = "-----BEGIN CERTIFICATE REQUEST-----\n";
        let foot = "-----END CERTIFICATE REQUEST-----\n";
        var isMultiple = false;
        var newCSRString = head;
        
        //Check if string size is a multiple of 64
        if (csrString.count % 64 == 0){
            isMultiple = true;
        }
        
        for (i, char) in csrString.enumerated() {
            newCSRString.append(char)
            
            if ((i != 0) && ((i+1) % 64 == 0)){
                newCSRString.append("\n")
            }
            
            if ((i == csrString.count-1) && !isMultiple){
                newCSRString.append("\n")
            }
            
        }
        
        newCSRString = newCSRString+foot
        
        return newCSRString
    }
    
    
    func buldCertificationRequestInfo(_ publicKeyBits:Data) -> Data{
        var certificationRequestInfo = Data(capacity: 256)
        
        //Add version
        let version: [UInt8] = [0x02, 0x01, 0x00] // ASN.1 Representation of integer with value 1
        certificationRequestInfo.append(version, count: version.count)
        
        //Add subject
        var subject = Data(capacity: 256)
        if countryName != nil{
            appendSubjectItem(OBJECT_countryName, value: countryName!, into: &subject)
        }
        
        if stateOrProvinceName != nil {
            appendSubjectItem(OBJECT_stateOrProvinceName, value: stateOrProvinceName!, into: &subject)
        }
        
        if localityName != nil {
            appendSubjectItem(OBJECT_localityName, value: localityName!, into: &subject)
        }
        
        if organizationName != nil{
            appendSubjectItem(OBJECT_organizationName, value: organizationName!, into: &subject)
        }
        
        if organizationUnitName != nil {
            appendSubjectItem(OBJECT_organizationalUnitName, value: organizationUnitName!, into: &subject)
        }
        
        if commonName != nil{
            appendSubjectItem(OBJECT_commonName, value: commonName!, into: &subject)
        }
        
        enclose(&subject, by: SEQUENCE_tag)// Enclose into SEQUENCE
        
        subjectDER = subject
        
        certificationRequestInfo.append(subject)
        
        //Add public key info
        let publicKeyInfo = buildPublicKeyInfo(publicKeyBits)
        certificationRequestInfo.append(publicKeyInfo)
        
        // Add attributes
        let attributes:[UInt8] = [0xA0, 0x00]
        certificationRequestInfo.append(attributes, count: attributes.count)
        
        enclose(&certificationRequestInfo, by: SEQUENCE_tag) // Enclose into SEQUENCE
        
        return certificationRequestInfo
    }
    
    // Utility class methods ...
    func buildPublicKeyInfo(_ publicKeyBits:Data)-> Data{
        
        var publicKeyInfo = Data(capacity: 390)
        
        switch keyAlgorithm! {
        case .rsa:
            publicKeyInfo.append(OBJECT_rsaEncryptionNULL, count: OBJECT_rsaEncryptionNULL.count)
        case .ec:
            publicKeyInfo.append(OBJECT_ecPubicKey, count: OBJECT_ecPubicKey.count)
            publicKeyInfo.append(OBJECT_ecEncryptionNULL, count: OBJECT_ecEncryptionNULL.count)
        }
        
        enclose(&publicKeyInfo, by: SEQUENCE_tag) // Enclose into SEQUENCE
        
        var publicKeyASN = Data(capacity: 260)
        switch keyAlgorithm!  {
        case .ec:
            let key = getPublicKey(publicKeyBits)
            publicKeyASN.append(key)
            
        default:
            
            let mod = getPublicKeyMod(publicKeyBits)
            let integer:UInt8 = 0x02 //Integer
            publicKeyASN.append(integer)
            appendDERLength(mod.count, into: &publicKeyASN)
            publicKeyASN.append(mod)
            
            let exp = getPublicKeyExp(publicKeyBits)
            publicKeyASN.append(integer)
            appendDERLength(exp.count, into: &publicKeyASN)
            publicKeyASN.append(exp)
            
            enclose(&publicKeyASN, by: SEQUENCE_tag)// Enclose into ??
        }
        
        prependByte(0x00, into: &publicKeyASN) //Prepend 0 (?)
        appendBITSTRING(publicKeyASN, into: &publicKeyInfo)
        
        enclose(&publicKeyInfo, by: SEQUENCE_tag) // Enclose into SEQUENCE
        
        return publicKeyInfo
    }
    
    func appendSubjectItem(_ what:[UInt8], value: String, into: inout Data ) ->(){
        
        if what.count != 5{
            print("Error: attempting to a non-subject item")
            return
        }
        
        var subjectItem = Data(capacity: 128)
        
        subjectItem.append(what, count: what.count)
        appendUTF8String(string: value, into: &subjectItem)
        enclose(&subjectItem, by: SEQUENCE_tag)
        enclose(&subjectItem, by: SET_tag)
        
        into.append(subjectItem)
    }
    
    func appendUTF8String(string: String, into: inout Data) ->(){
        
        let strType:UInt8 = 0x0C //UTF8STRING
        
        into.append(strType)
        appendDERLength(string.lengthOfBytes(using: String.Encoding.utf8), into: &into)
        into.append(string.data(using: String.Encoding.utf8)!)
    }
    
    func appendDERLength(_ length: Int, into: inout Data){
        
        assert(length < 0x8000)
        
        if length < 128{
            let d = UInt8(length)
            into.append(d)
            
        }else if (length < 0x100){
            
            var d: [UInt8] = [0x81, UInt8(length & 0xFF)]
            into.append(&d, count: d.count)
            
        }else if length < 0x8000{
            
            let preRes:UInt = UInt(length & 0xFF00)
            let res = UInt8(preRes >> 8)
            var d: [UInt8] = [0x82, res, UInt8(length & 0xFF)]
            into.append(&d, count: d.count)
        }
    }
    
    func appendBITSTRING(_ data: Data, into: inout Data)->(){
        
        let strType:UInt8 = 0x03 //BIT STRING
        into.append(strType)
        appendDERLength(data.count, into: &into)
        into.append(data)
    }
    
    func enclose(_ data: inout Data, by: UInt8){
        
        var newData = Data(capacity: data.count + 4)
        
        newData.append(by)
        appendDERLength(data.count, into: &newData)
        newData.append(data)
        
        data = newData
    }
    
    func prependByte(_ byte: UInt8, into: inout Data)->(){
        
        var newData = Data(capacity: into.count + 1)
        
        newData.append(byte)
        newData.append(into)
        
        into = newData
    }
    
    func getPublicKey(_ publicKeyBits:Data)->Data{
        
        //Current only supports uncompressed keys, 65=1+32+32
        var iterator = 0
        
        _ = derEncodingSpecificSize(publicKeyBits, at: &iterator, numOfBytes: 8)
        
        let range:Range<Int> = 0 ..< 65
        
        return publicKeyBits.subdata(in: range)
    }
    
    // From http://stackoverflow.com/questions/3840005/how-to-find-out-the-modulus-and-exponent-of-rsa-public-key-on-iphone-objective-c
    
    func getPublicKeyExp(_ publicKeyBits:Data)->Data{
        
        var iterator = 0
        
        iterator+=1 // TYPE - bit stream - mod + exp
        _ = derEncodingGetSizeFrom(publicKeyBits, at: &iterator) // Total size
        
        iterator+=1 // TYPE - bit stream mod
        let modSize = derEncodingGetSizeFrom(publicKeyBits, at: &iterator)
        iterator += modSize
        
        iterator+=1 // TYPE - bit stream exp
        let expSize = derEncodingGetSizeFrom(publicKeyBits, at: &iterator)
        
        let range:Range<Int> = iterator ..< (iterator + expSize)
        
        return publicKeyBits.subdata(in: range)
    }
    
    func getPublicKeyMod(_ publicKeyBits: Data)->Data{
        
        var iterator = 0
        
        iterator+=1 // TYPE - bit stream - mod + exp
        _ = derEncodingGetSizeFrom(publicKeyBits, at: &iterator)
        
        iterator+=1 // TYPE - bit stream mod
        let modSize = derEncodingGetSizeFrom(publicKeyBits, at: &iterator)
        
        let range:Range<Int> = iterator ..< (iterator + modSize)
        
        return publicKeyBits.subdata(in: range)
    }
    
    func derEncodingSpecificSize(_ buf: Data, at iterator: inout Int, numOfBytes: Int)->Int{
        
        var data = [UInt8](repeating: 0, count: buf.count)
        buf.copyBytes(to: &data, count: buf.count)
        
        if data[0] != 0x04{
            print("Error, framework only supports uncompressed keys")
        }
        
        return buf.count
    }
    
    func derEncodingGetSizeFrom(_ buf: Data, at iterator: inout Int)->Int{
        
        var data = [UInt8](repeating: 0, count: buf.count)
        buf.copyBytes(to: &data, count: buf.count)
        
        var itr = iterator
        var numOfBytes = 1
        var ret = 0
        
        if data[itr] > 0x80{
            numOfBytes = Int((data[itr] - 0x80))
            itr += 1
        }
        
        for index in 0 ..< numOfBytes {
            ret = (ret * 0x100) + Int(data[itr + index])
        }
        
        iterator = itr + numOfBytes
        
        return ret
    }
}




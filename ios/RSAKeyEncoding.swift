//
//  RSAKeyEncoding.swift
//  RNECRSA

import Foundation

class RSAKeyEncoding: NSObject {
    
    // ASN.1 identifiers
    private let bitStringIdentifier: UInt8 = 0x03
    private let sequenceIdentifier: UInt8 = 0x30
    
    // ASN.1 AlgorithmIdentfier for RSA encryption: OID 1 2 840 113549 1 1 1 and NULL
    private let algorithmIdentifierForRSAEncryption: [UInt8] = [0x30, 0x0d, 0x06,
                                                                0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]
    
    /// Converts the DER encoding of an RSA public key that is either fetched from the
    /// keychain (e.g. by using `SecItemCopyMatching(_:_:)`) or retrieved in another way
    /// (e.g. by using `SecKeyCopyExternalRepresentation(_:_:)`), to a format typically
    /// used by tools and programming languages outside the Apple ecosystem (such as
    /// OpenSSL, Java, PHP and Perl). The DER encoding of an RSA public key created by
    /// iOS is represented with the ASN.1 RSAPublicKey type as defined by PKCS #1.
    /// However, many systems outside the Apple ecosystem expect the DER encoding of a
    /// key to be represented with the ASN.1 SubjectPublicKeyInfo type as defined by
    /// X.509. The two types are related in a way that if the SubjectPublicKeyInfo’s
    /// algorithm field contains the rsaEncryption object identifier as defined by
    /// PKCS #1, the subjectPublicKey field shall contain the DER encoding of an
    /// RSAPublicKey type.
    ///
    /// - Parameter rsaPublicKeyData: A data object containing the DER encoding of an
    ///     RSA public key, which is represented with the ASN.1 RSAPublicKey type.
    /// - Returns: A data object containing the DER encoding of an RSA public key, which
    ///     is represented with the ASN.1 SubjectPublicKeyInfo type.
    func convertToX509EncodedKey(_ rsaPublicKeyData: Data) -> Data {
        var derEncodedKeyBytes = [UInt8](rsaPublicKeyData)
        
        // Insert ASN.1 BIT STRING bytes at the beginning of the array
        derEncodedKeyBytes.insert(0x00, at: 0)
        derEncodedKeyBytes.insert(contentsOf: lengthField(of: derEncodedKeyBytes), at: 0)
        derEncodedKeyBytes.insert(bitStringIdentifier, at: 0)
        
        // Insert ASN.1 AlgorithmIdentifier bytes at the beginning of the array
        derEncodedKeyBytes.insert(contentsOf: algorithmIdentifierForRSAEncryption, at: 0)
        
        // Insert ASN.1 SEQUENCE bytes at the beginning of the array
        derEncodedKeyBytes.insert(contentsOf: lengthField(of: derEncodedKeyBytes), at: 0)
        derEncodedKeyBytes.insert(sequenceIdentifier, at: 0)
        
        return Data(derEncodedKeyBytes)
    }
    
    private func lengthField(of valueField: [UInt8]) -> [UInt8] {
        var length = valueField.count
        
        if length < 128 {
            return [ UInt8(length) ]
        }
        
        // Number of bytes needed to encode the length
        let lengthBytesCount = Int((log2(Double(length)) / 8) + 1)
        
        // First byte encodes the number of remaining bytes in this field
        let firstLengthFieldByte = UInt8(128 + lengthBytesCount)
        
        var lengthField: [UInt8] = []
        for _ in 0..<lengthBytesCount {
            // Take the last 8 bits of length
            let lengthByte = UInt8(length & 0xff)
            // Insert them at the beginning of the array
            lengthField.insert(lengthByte, at: 0)
            // Delete the last 8 bits of length
            length = length >> 8
        }
        
        // Insert firstLengthFieldByte at the beginning of the array
        lengthField.insert(firstLengthFieldByte, at: 0)
        
        return lengthField
    }
}


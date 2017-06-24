package com.RNRSA;


import android.util.Base64;

import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;

import java.io.IOException;

import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Primitive;
import org.spongycastle.asn1.pkcs.PrivateKeyInfo;
import org.spongycastle.asn1.pkcs.RSAPublicKey;
import org.spongycastle.asn1.pkcs.RSAPrivateKey;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.asn1.x509.RSAPublicKeyStructure;
import org.spongycastle.util.io.pem.PemObject;
import org.spongycastle.util.io.pem.PemWriter;
import org.spongycastle.util.io.pem.PemReader;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RSA {

    public static final String ALGORITHM = "RSA";

    private static final String PUBLIC_HEADER = "RSA PUBLIC KEY";
    private static final String PRIVATE_HEADER = "RSA PRIVATE KEY";

    private PublicKey publicKey;
    private PrivateKey privateKey;

    public String getPublicKey() throws IOException {
        byte[] pkcs1PublicKey = publicKeyToPkcs1(this.publicKey);

        return dataToPem(PUBLIC_HEADER, pkcs1PublicKey);
    }

    public String getPrivateKey() throws IOException {
        byte[] pkcs1PrivateKey = privateKeyToPkcs1(this.privateKey);

        return dataToPem(PRIVATE_HEADER, pkcs1PrivateKey);
    }

    public void setPublicKey(String publicKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException  {
        byte[] pkcs1PublicKey = pemToData(publicKey);
        this.publicKey = pkcs1ToPublicKey(pkcs1PublicKey);
    }

    public void setPrivateKey(String privateKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException  {
        byte[] pkcs1PrivateKey = pemToData(privateKey);
        this.privateKey = pkcs1ToPrivateKey(pkcs1PrivateKey);
    }

    public String encrypt(String message) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException {
        String encodedMessage = null;
        final Cipher cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
        byte[] data = cipher.doFinal(message.getBytes(UTF_8));
        encodedMessage = Base64.encodeToString(data, Base64.DEFAULT);

        return encodedMessage;
    }

    public String decrypt(String encodedMessage) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException {
        String message = null;
        byte[] cipherText = Base64.decode(encodedMessage, Base64.DEFAULT);
        final Cipher cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
        byte[] data = cipher.doFinal(cipherText);
        message = new String(data, UTF_8);

        return message;
    }

    private String dataToPem(String header, byte[] keyData) throws IOException {
        PemObject pemObject = new PemObject(header, keyData);
        StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter);
        pemWriter.writeObject(pemObject);
        pemWriter.close();
        return stringWriter.toString();
    }

    private byte[] pemToData(String pemKey) throws IOException {
        Reader keyReader = new StringReader(pemKey);
        PemReader pemReader = new PemReader(keyReader);
        PemObject pemObject = pemReader.readPemObject();
        return pemObject.getContent();
    }

    private PublicKey pkcs1ToPublicKey(byte[] pkcs1PublicKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        ASN1InputStream in = new ASN1InputStream(pkcs1PublicKey);
        ASN1Primitive obj = in.readObject();
        RSAPublicKey keyStruct = RSAPublicKey.getInstance(obj);
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(keyStruct.getModulus(), keyStruct.getPublicExponent());
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        return keyFactory.generatePublic(keySpec);
    }

    private PrivateKey pkcs1ToPrivateKey(byte[] pkcs1PrivateKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        ASN1InputStream in = new ASN1InputStream(pkcs1PrivateKey);
        ASN1Primitive obj = in.readObject();
        RSAPrivateKey keyStruct = RSAPrivateKey.getInstance(obj);
        RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(keyStruct.getModulus(), keyStruct.getPrivateExponent());
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        return keyFactory.generatePrivate(keySpec);
    }

    private byte[] publicKeyToPkcs1(PublicKey publicKey) throws IOException {
        SubjectPublicKeyInfo spkInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        ASN1Primitive primitive = spkInfo.parsePublicKey();
        return primitive.getEncoded();
    }

    private byte[] privateKeyToPkcs1(PrivateKey privateKey) throws IOException {
        PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(privateKey.getEncoded());
        ASN1Encodable encodeable = pkInfo.parsePrivateKey();
        ASN1Primitive primitive = encodeable.toASN1Primitive();
        return primitive.getEncoded();
    }


    public void generate() throws IOException, NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM);
        kpg.initialize(2048);

        KeyPair keyPair = kpg.genKeyPair();
        this.publicKey = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();
    }

}
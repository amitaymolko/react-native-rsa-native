package com.RNRSA;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.ECGenParameterSpec;

import java.util.Date;
import java.math.BigInteger;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;

import java.io.IOException;
import java.lang.System;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import static android.security.keystore.KeyProperties.*;
import static java.nio.charset.StandardCharsets.UTF_8;

public class RSA {

    public static final String ALGORITHM = "EC";

    private static final String PUBLIC_HEADER = "EC PUBLIC KEY";
    private static final String PRIVATE_HEADER = "EC PRIVATE KEY";

    private String keyStoreId;
    private String keyTag;

    private PublicKey publicKey;
    private PrivateKey privateKey;

    public RSA() {
    }

    public RSA(String keyTag, String keyStoreId) throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException, IOException, CertificateException, NoSuchProviderException, InvalidAlgorithmParameterException {
        this.keyTag = keyTag;
        this.keyStoreId = keyStoreId;

        this.loadFromKeystore();
    }

    public RSA(String keyTag, String keyStoreId, KeyPair pair) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, SignatureException, InvalidKeyException, InvalidKeySpecException, KeyStoreException, CertificateException, UnrecoverableEntryException {
        this.keyTag = keyTag;
        this.keyStoreId = keyStoreId;

        this.deletePrivateKey();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();

        KeyStore keyStore = this.getKeyStore();
        keyStore.load(null);
        Certificate cert = genX509cert(pair);
        Certificate[] chain = new Certificate[]{cert};
        keyStore.setKeyEntry(this.keyTag, pair.getPrivate(), null, chain);
    }

    public String toPem(Key key) throws IOException {
        StringWriter sw = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(sw);
        pemWriter.writeObject(key);
        pemWriter.close();
        return sw.toString();
    }

    public String getPublicKey() throws IOException {
        return toPem(this.publicKey);
    }

    public String getPrivateKey() throws IOException {
        return toPem(this.privateKey);
    }

    public void setPublicKey(String publicKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        this.publicKey = pkcs1ToPublicKey(publicKey);
    }

    public void setPrivateKey(String privateKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        KeyPair kp = pkcs1ToPrivateKey(privateKey);
        this.privateKey = kp.getPrivate();
        this.publicKey = kp.getPublic();
    }

    private static Certificate genX509cert(KeyPair pair) throws InvalidKeyException, NoSuchProviderException, SignatureException, OperatorCreationException, IOException, CertificateException {

        X500Name issuer = new X500Name("CN=Vida Self Signed Cert");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis());
        Date notAfter = new Date(System.currentTimeMillis() + Long.valueOf("788400000000"));
        X500Name subject = new X500Name("CN=Vida Self Signed Cert");;
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded());

        // Generate the certificate
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, publicKeyInfo);

        // Set certificate extensions
        certBuilder.addExtension(X509Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.keyAgreement));

        // Sign the certificate
        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA1WithRSAEncryption");
        ContentSigner contentSigner = contentSignerBuilder.build(pair.getPrivate());

        X509CertificateHolder holder = certBuilder.build(contentSigner);

        // Retrieve the certificate from holder
        InputStream is1 = new ByteArrayInputStream(holder.getEncoded());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate generatedCertificate = cf.generateCertificate(is1);
        return generatedCertificate;
    }

    private final Cipher getCipher() throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, NoSuchProviderException {

        if(this.keyTag != null){
            return Cipher.getInstance("RSA/None/OAEPWithSHA-1AndMGF1Padding", "AndroidKeyStoreBCWorkaround");
        }else{
            return Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding");
        }
    }

    private final Signature getSignature() throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, NoSuchProviderException {
        return Signature.getInstance("SHA512withRSA");
    }

    // This function will be called by encrypt and encrypt64
    private byte[] encrypt(byte[] data) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, NoSuchProviderException {
        String encodedMessage = null;
        final Cipher cipher = getCipher();
        cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
        byte[] cipherBytes = cipher.doFinal(data);
        return cipherBytes;
    }

    // Base64 input
    public String encrypt64(String b64Message) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, NoSuchProviderException {
        byte[] data = Base64.decode(b64Message, Base64.DEFAULT);
        byte[] cipherBytes = encrypt(data);
        return Base64.encodeToString(cipherBytes, Base64.DEFAULT);
    }

    // UTF-8 input
    public String encrypt(String message) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, NoSuchProviderException  {
        byte[] data = message.getBytes(UTF_8);
        byte[] cipherBytes = encrypt(data);
        return Base64.encodeToString(cipherBytes, Base64.DEFAULT);
    }

    private byte[] decrypt(byte[] cipherBytes) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, NoSuchProviderException {
        String message = null;
        final Cipher cipher = getCipher();
        cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
        byte[] data = cipher.doFinal(cipherBytes);
        return data;
    }

    // UTF-8 input
    public String decrypt(String message) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, NoSuchProviderException  {
        byte[] cipherBytes = message.getBytes(UTF_8);
        byte[] data = decrypt(cipherBytes);
        return new String(data, UTF_8);
    }

    // Base64 input
    public String decrypt64(String b64message) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, NoSuchProviderException  {
        byte[] cipherBytes = Base64.decode(b64message, Base64.DEFAULT);
        byte[] data = decrypt(cipherBytes);
        return Base64.encodeToString(data, Base64.DEFAULT);
    }

    private String sign(byte[] messageBytes) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException, NoSuchProviderException {
        Signature privateSignature = getSignature();
        privateSignature.initSign(this.privateKey);
        privateSignature.update(messageBytes);
        byte[] signature = privateSignature.sign();
        return Base64.encodeToString(signature, Base64.DEFAULT);
    }

    // b64 message
    public String sign64(String b64message) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException, NoSuchProviderException  {
        byte[] messageBytes = Base64.decode(b64message, Base64.DEFAULT);
        return sign(messageBytes);
    }

    //utf-8 message
    public String sign(String message) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException, NoSuchProviderException  {
        byte[] messageBytes = message.getBytes(UTF_8);
        return sign(messageBytes);
    }

    private boolean verify(byte[] signatureBytes, byte[] messageBytes) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException, NoSuchProviderException {
        Signature publicSignature = getSignature();
        publicSignature.initVerify(this.publicKey);
        publicSignature.update(messageBytes);
        return publicSignature.verify(signatureBytes);
    }

    // b64 message
    public boolean verify64(String signature, String message) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException, NoSuchProviderException {
        Signature publicSignature = getSignature();
        publicSignature.initVerify(this.publicKey);
        byte[] messageBytes = Base64.decode(message, Base64.DEFAULT);
        byte[] signatureBytes = Base64.decode(signature, Base64.DEFAULT);
        return verify(signatureBytes, messageBytes);
    }

    // utf-8 message
    public boolean verify(String signature, String message) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException, NoSuchProviderException {
        Signature publicSignature = getSignature();
        publicSignature.initVerify(this.publicKey);
        byte[] messageBytes = message.getBytes(UTF_8);
        byte[] signatureBytes = Base64.decode(signature, Base64.DEFAULT);
        return verify(signatureBytes, messageBytes);
    }

    private PublicKey pkcs1ToPublicKey(String publicKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Reader keyReader = null;
        try {
            keyReader = new StringReader(publicKey);
            PEMParser pemParser = new PEMParser(keyReader);
            SubjectPublicKeyInfo subjectPublicKeyInfo = (SubjectPublicKeyInfo) pemParser.readObject();
            X509EncodedKeySpec spec = new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded());
            return KeyFactory.getInstance("EC").generatePublic(spec);
        } finally {
            if (keyReader != null) {
                keyReader.close();
            }
        }
    }

    private KeyPair pkcs1ToPrivateKey(String pkcs1PrivateKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Reader reader = new StringReader(pkcs1PrivateKey);
        KeyPair res = null;
        PEMParser parser = null;
        try {
            parser = new PEMParser(reader);
            PEMKeyPair pair = (PEMKeyPair) parser.readObject();
            KeyPair kp = new JcaPEMKeyConverter().getKeyPair(pair);
            res = kp;
        } finally {
            if (parser != null) {
                parser.close();
            }
            if (reader != null) {
                reader.close();
            }
        }
        return res;
    }

    private byte[] publicKeyToPkcs1(PublicKey publicKey) throws IOException {
        SubjectPublicKeyInfo spkInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        System.out.print(spkInfo);
        ASN1Primitive primitive = spkInfo.parsePublicKey();
        return primitive.getEncoded();
    }

    private KeyStore getKeyStore() throws KeyStoreException {
        return KeyStore.getInstance(this.keyStoreId);
    }

    public void loadFromKeystore() throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException, IOException, CertificateException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyStore keyStore = this.getKeyStore();
        keyStore.load(null);
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(this.keyTag, null);
        if ( privateKeyEntry == null ) {
            this.generate(this.keyTag);
        }
        this.privateKey = privateKeyEntry.getPrivateKey();
        this.publicKey = privateKeyEntry.getCertificate().getPublicKey();
    }

    public void deletePrivateKey() throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException, IOException, CertificateException {
        KeyStore keyStore = this.getKeyStore();
        keyStore.load(null);
        keyStore.deleteEntry(this.keyTag);
        this.privateKey = null;
        this.publicKey = null;
    }

    public void generate() throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM);

        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256k1");

        kpg.initialize(ecSpec);

        KeyPair keyPair = kpg.genKeyPair();
        this.publicKey = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();
    }

    public void generate(String keyTag) throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException, KeyStoreException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance(this.keyStoreId);
        keyStore.load(null);
        try {
            keyStore.deleteEntry(this.keyTag);
        }
        catch (NullPointerException exc) {
            // On older android versions, this can occurr when the keytag does not already exist
        }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM);

        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256k1");

        kpg.initialize(new KeyGenParameterSpec.Builder(
                keyTag,
                PURPOSE_ENCRYPT | PURPOSE_DECRYPT | PURPOSE_SIGN | PURPOSE_VERIFY
        )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .setAlgorithmParameterSpec(ecSpec)
                .build());

        KeyPair keyPair = kpg.genKeyPair();
        this.publicKey = keyPair.getPublic();
    }

    public byte[] ecdh(RSA pubKey) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
        ka.init(this.privateKey);

        Key ret = ka.doPhase(pubKey.publicKey, true);

        return ret.getEncoded();
    }
}

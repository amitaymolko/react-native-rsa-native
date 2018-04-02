package com.RNRSA;

import android.util.Log;

import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class Pbkdf2Rng extends Random {
    public static final String PBKDF2_ALGORITHM = "PBKDF2withHmacSHA1";
    private static final int seedLen = 16;
    private final JcaJceHelper helper = new BCJcaJceHelper();
    private int maxRead;
    private byte[] bytes;
    private byte[] seed;
    private int index;
    private int fillLen;

    private String b2s(byte[] bytes) {
        String out = "0x";
        for (int i=0; i<bytes.length; i++) {
            out += String.format("%02x", bytes[i]);
        }
        return out;
    }
    private String b2s(char[] chars) {
        String out = "0x";
        for (int i=0; i<chars.length; i++) {
            out += String.format("%02x", (int) chars[i]);
        }
        return out;
    }

    private void generateMoreBytes() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        // generate more bytes
        char[] cseed = new char[this.seedLen];
        for (int i=0; i<cseed.length; i++) {
            cseed[i] = (char) (seed[i] & 0x007F);
        }
        byte[] salt = new byte[1];
        salt[0] = 0;

        PBEKeySpec spec = new PBEKeySpec(cseed, salt, 1, (this.fillLen+this.seedLen)*8);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        byte[] newBytes = factory.generateSecret(spec).getEncoded();

        // replenish seed
        for (int i=0; i<this.seedLen; i++) {
            this.seed[this.seedLen-i-1] = newBytes[this.fillLen+i];
        }

        // Save away remaining bytes in buffer and copy new bytes in
        byte[] tmp = null;
        if (this.index >= 0) {
            tmp = new byte[this.index+1];
            System.arraycopy(this.bytes, 0, tmp, 0, this.index+1);
        }
        System.arraycopy(newBytes, 0, this.bytes, 0, this.fillLen);
        if (this.index >= 0) {
            System.arraycopy(tmp, 0, this.bytes, this.fillLen, this.index+1);
        }
        this.index += this.fillLen;
    }

    public Pbkdf2Rng(byte[] seed, int bits) {
        this.fillLen = 32*bits;
        this.maxRead = bits;
        this.bytes = new byte[this.fillLen + this.maxRead];
        this.index = -1;
        this.seed = new byte[this.seedLen];
        int len = (seed.length < this.seedLen) ? seed.length : this.seedLen;
        System.arraycopy(seed, 0, this.seed, 0, len);
        try {
            this.generateMoreBytes();
        } catch (NoSuchAlgorithmException|InvalidKeySpecException|NoSuchProviderException e) {
            Log.e("VIDA", "Failed to generate more bytes\n" + e.toString() + e.getMessage() + Log.getStackTraceString(e));
        }
    }

    protected int next (int bits) {
        if (bits > 32 || bits < 0) {
            throw new IllegalArgumentException("bits out of range "+ bits);
        }
        byte[] tmp = new byte[(bits+7)/8];
        this.nextBytes(tmp);
        int ret = 0;
        for (int i=0; i<tmp.length; i++) {
            ret |= tmp[i] << (i*8);
        }
        return ret;
    }
    public void nextBytes(byte[] bytes) {
        if (bytes.length > this.maxRead) {
            throw new IllegalArgumentException("too many bytes requested " + bytes.length);
        }
        if (this.index < bytes.length-1) {
            try {
                this.generateMoreBytes();
            } catch (NoSuchAlgorithmException|InvalidKeySpecException|NoSuchProviderException e) {
                Log.e("VIDA", "Failed to generate more bytes: " + e.toString() + e.getMessage() + Log.getStackTraceString(e));
            }
        }
        for(int i=0; i<bytes.length; i++) {
            bytes[i] = this.bytes[this.index-i];
        }
        this.index -= bytes.length;
    }
}

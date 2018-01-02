package com.RNRSA;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;

/**
 * This class wraps an AndroidKeyStoreRSAPrivateKey object to add the RSAPrivateKeyInterface
 */

public class AndroidKeyStoreRSAPrivateKeyOAEP extends AndroidKeyStoreRSAPrivateKey implements RSAPrivateKey {

    private final AndroidKeyStoreRSAPrivateKey delegate;


    public AndroidKeyStoreRSAPrivateKeyOAEP(AndroidKeyStoreRSAPrivateKey superclass) {

        this.delegate = superclass;

    }


    public BigInteger getModulus() {
        return delegate.getModulus();
    }

}
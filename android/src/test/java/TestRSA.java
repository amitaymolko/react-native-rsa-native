import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;
import org.junit.Assert;

import com.RNRSA.RSA;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import static org.hamcrest.CoreMatchers.*;

class Converter {
    public static String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for(byte b: a)
        sb.append(String.format("%02x", b));
        return sb.toString();
    }
}

/**
 * Created by erik on 7/19/2018.
 */
@RunWith(MockitoJUnitRunner.class)
public class TestRSA {
    @Before
    public void setUp() throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    @Test
    public void testECGenerate() throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException, IOException, CertificateException, NoSuchProviderException, InvalidAlgorithmParameterException {
        RSA r = new RSA();
        r.generate();
        Assert.assertThat(r.getPublicKey(), containsString("PUBLIC KEY"));
    }

    @Test
    public void testECPemRead() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        String x = "-----BEGIN EC PRIVATE KEY-----\n" +
                "MHQCAQEEIDDwZeEKPyMwKcK4bMwGqOPvyv9rIlTRcp5Yq0I8a5wSoAcGBSuBBAAK\n" +
                "oUQDQgAERC89tEvN6QNBNhmk8j/9MvgRWkr8ooloa8RWCCKx2WWvuJrs4PclgrPa\n" +
                "bUGuqKzjXEAyjz7f3/kMviBfwsx0YQ==\n" +
                "-----END EC PRIVATE KEY-----\n";
        RSA r = new RSA();
        r.setPrivateKey(x);

        Assert.assertThat(r.getPublicKey(), containsString("PUBLIC KEY"));
        Assert.assertThat(r.getPrivateKey(), containsString("EC PRIVATE KEY"));
    }

    @Test
    public void testECDH() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchProviderException, InvalidKeyException {
        String x = "-----BEGIN EC PRIVATE KEY-----\n" +
                "MHQCAQEEIDDwZeEKPyMwKcK4bMwGqOPvyv9rIlTRcp5Yq0I8a5wSoAcGBSuBBAAK\n" +
                "oUQDQgAERC89tEvN6QNBNhmk8j/9MvgRWkr8ooloa8RWCCKx2WWvuJrs4PclgrPa\n" +
                "bUGuqKzjXEAyjz7f3/kMviBfwsx0YQ==\n" +
                "-----END EC PRIVATE KEY-----\n";
        String y = "-----BEGIN PUBLIC KEY-----\n" +
                "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEh7SDE/IUXojqrY8SKooFKnQL84/ZHlDq\n" +
                "9xc2iFYJECC9/6moXSa0rnVzQ6NBw6s0xhk5s5KbVrEivfyjfpgoJg==\n" +
                "-----END PUBLIC KEY-----\n";
        RSA r = new RSA();
        r.setPrivateKey(x);
        Assert.assertThat(r.getPublicKey(), containsString("PUBLIC KEY"));
        Assert.assertThat(r.getPrivateKey(), containsString("EC PRIVATE KEY"));

        RSA r2 = new RSA();
        r.setPublicKey(y);

        byte[] shared_secret = r.ecdh(r2);

        String hex = Converter.byteArrayToHex(shared_secret);
        Assert.assertEquals("556Y", hex);
    }
}

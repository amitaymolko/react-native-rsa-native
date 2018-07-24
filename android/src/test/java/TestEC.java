import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;
import org.junit.Assert;

import com.RNRSA.EC;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import static org.hamcrest.CoreMatchers.*;

class Converter {
    static String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for(byte b: a)
        sb.append(String.format("%02x", b));
        return sb.toString();
    }

    static byte[] hexToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}

/**
 * Created by erik on 7/19/2018.
 */
@RunWith(MockitoJUnitRunner.class)
public class TestEC {
    EC priv;
    EC pub;

    @BeforeClass
    public static void setUpClass() throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

    }

    @Before
    public void setUp() throws Exception {
        String x = "-----BEGIN EC PRIVATE KEY-----\n" +
                "MHQCAQEEIDDwZeEKPyMwKcK4bMwGqOPvyv9rIlTRcp5Yq0I8a5wSoAcGBSuBBAAK\n" +
                "oUQDQgAERC89tEvN6QNBNhmk8j/9MvgRWkr8ooloa8RWCCKx2WWvuJrs4PclgrPa\n" +
                "bUGuqKzjXEAyjz7f3/kMviBfwsx0YQ==\n" +
                "-----END EC PRIVATE KEY-----\n";
        String y = "-----BEGIN PUBLIC KEY-----\n" +
                "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEh7SDE/IUXojqrY8SKooFKnQL84/ZHlDq\n" +
                "9xc2iFYJECC9/6moXSa0rnVzQ6NBw6s0xhk5s5KbVrEivfyjfpgoJg==\n" +
                "-----END PUBLIC KEY-----\n";
        priv = new EC();
        priv.setPrivateKey(x);

        pub = new EC();
        pub.setPublicKey(y);
    }

    @Test
    public void testECGenerate() throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException, IOException, CertificateException, NoSuchProviderException, InvalidAlgorithmParameterException {
        EC r = new EC();
        r.generate();
        Assert.assertThat(r.getPublicKey(), containsString("PUBLIC KEY"));
    }

    @Test
    public void testECPemRead() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        Assert.assertThat(priv.getPublicKey(), containsString("PUBLIC KEY"));
        Assert.assertThat(priv.getPrivateKey(), containsString("EC PRIVATE KEY"));
    }

    @Test
    public void testECDH() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchProviderException, InvalidKeyException, ShortBufferException {
        byte[] shared_secret = priv.ecdh(pub);
        String hex = Converter.byteArrayToHex(shared_secret);
        Assert.assertEquals("c8c62ca5ed8707731afe8d5fbb3386a4b91eab8ec495d2e0bcadb585b666857f", hex);
    }

    @Test
    public void testSign() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchProviderException, InvalidKeyException, ShortBufferException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, SignatureException {
        byte[] msg = Converter.hexToByteArray("deadbeef");
        byte[] sig = priv.sign(msg);
        Boolean res = priv.verify(sig, msg);
        Assert.assertEquals(true, res);
    }
}

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import com.RNRSA.RSA;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

/**
 * Created by erik on 7/19/2018.
 */
@RunWith(MockitoJUnitRunner.class)
public class TestRSA {
    @Test
    public void testRSAGenerate() throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException, IOException, CertificateException, NoSuchProviderException, InvalidAlgorithmParameterException {
        RSA r = new RSA();
        r.generate();
    }
}

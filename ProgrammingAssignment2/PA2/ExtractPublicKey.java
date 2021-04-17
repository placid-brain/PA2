import java.io.*;
import java.nio.*;
import java.security.*;
import java.security.spec.*;
 


public class ExtractPublicKey {
    InputStream fis = new FileInputStream("/Users/placid_brain/sch_assgn/PA2 Cert gen/cacsertificate.crt");
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    X509Certificate CAcert =(X509Certificate)cf.generateCertificate(fis);
    PublicKey key = CAcert.getPublicKey();
    public abstract void checkValidity();
    public abstract void verify(PublicKey key);
    




    
}

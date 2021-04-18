import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class ClientWithCP1 {

    //step 1: making an object of x509cert
    InputStream fis = new FileInputStream("/Users/placid_brain/sch_assgn/ProgrammingAssignment2/PA2/cacsertificate.crt");
    CertificateFactory cse_cert = CertificateFactory.getInstance("X.509");
    X509Certificate CAcert =(X509Certificate)cse_cert.generateCertificate(fis);
}

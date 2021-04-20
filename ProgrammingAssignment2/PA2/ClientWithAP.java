import java.io.*;
import java.net.Socket;
import java.security.Key;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.PublicKey;
import java.util.Base64;
import java.security.cert.CertificateFactory;

public class ClientWithAP {

    public static void main(String[] args) {


        //Extract public key of the server
        InputStream fis = null;
        try {
            fis = new FileInputStream("/home/myat00/Desktop/PA2/ProgrammingAssignment2/PA2/cacsertificate.crt");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        CertificateFactory cf = null;
        try {
            cf = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        X509Certificate CAcert = null;
        try {
            CAcert = (X509Certificate) cf.generateCertificate(fis);
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        PublicKey publicKey = CAcert.getPublicKey();


        String filename = "100.txt";
        if (args.length > 0) filename = args[0];

        String serverAddress = "localhost";
        if (args.length > 1) filename = args[1];

        int port = 4321;
        if (args.length > 2) port = Integer.parseInt(args[2]);

        int numBytes = 0;

        Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

        FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

        long timeStarted = System.nanoTime();

        try {

            System.out.println("Establishing connection to server...");

            // Connect to server and get the input and output streams
            clientSocket = new Socket(serverAddress, port);
            toServer = new DataOutputStream(clientSocket.getOutputStream());
            fromServer = new DataInputStream(clientSocket.getInputStream());

            //Hello SecStore, please prove your identity
            toServer.writeInt(2);
            //pass the client's message to the server
            toServer.writeUTF("Hello SecStore, please prove your identity");
            //receive the encrypted message from the server which is the proof of the identity of the server
            fromServer.readUTF();


            //request certificate signed by CA
            toServer.writeInt(3);

            //decrypt the signed certificate
            //receive the server's encrypted signed certificate in string format
            String signedCertFromServer = fromServer.readUTF();
            byte[] CertArray = Base64.getDecoder().decode(signedCertFromServer);

            //Convert the decoded Byte[] into certificate

            InputStream signed = new ByteArrayInputStream(CertArray);
            X509Certificate ServerCert = (X509Certificate) cf.generateCertificate(signed);


            //verification process
            ServerCert.checkValidity();
            ServerCert.verify(publicKey);


            //After the verification process, send the file

            System.out.println("Sending file...");

            // Send the filename
            toServer.writeInt(0); //writes zero
            toServer.writeInt(filename.getBytes().length);
            toServer.write(filename.getBytes());
            //toServer.flush();

            // Open the file
            fileInputStream = new FileInputStream(filename);
            bufferedFileInputStream = new BufferedInputStream(fileInputStream);

            byte[] fromFileBuffer = new byte[117];

            // Send the file
            for (boolean fileEnded = false; !fileEnded; ) {
                numBytes = bufferedFileInputStream.read(fromFileBuffer);
                fileEnded = numBytes < 117;

                toServer.writeInt(1);
                toServer.writeInt(numBytes);
                toServer.write(fromFileBuffer);
                toServer.flush();
            }

            bufferedFileInputStream.close();
            fileInputStream.close();

            System.out.println("Closing connection...");

        } catch (Exception e) {
            e.printStackTrace();
        }

        long timeTaken = System.nanoTime() - timeStarted;
        System.out.println("Program took: " + timeTaken / 1000000.0 + "ms to run");
    }

}

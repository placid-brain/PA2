import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.PrivateKey;
import java.util.Base64;

public class ServerFulfillingAP {

    public static void main(String[] args) {
        InputStream fis = null;
        try {
            fis = new FileInputStream("/home/myat00/Desktop/PA2/ProgrammingAssignment2/PA2/certificate_1004637.crt");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        CertificateFactory cf = null;
        try {
            cf = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        X509Certificate x509Certificate = null;
        try {
            x509Certificate = (X509Certificate) cf.generateCertificate(fis);
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        //get private key since we need private key to sign a message and send that message to the client.
        PrivateKey privateKey = null;
        try {
            privateKey = PrivateKeyReader.get("/home/myat00/Desktop/PA2/ProgrammingAssignment2/PA2/private_key.der");
        } catch (Exception e) {
            e.printStackTrace();
        }

        //create an RSAUtils object to be able to use encrypt and decrypt methods
        RSAUtils rsa = new RSAUtils();


        int port = 4321;
        if (args.length > 0) {
            port = Integer.parseInt(args[0]);
        }

        ServerSocket welcomeSocket = null;
        Socket connectionSocket = null;
        DataOutputStream toClient = null;
        DataInputStream fromClient = null;
        FileOutputStream fileOutputStream = null;
        BufferedOutputStream bufferedFileOutputStream = null;

        try {
            welcomeSocket = new ServerSocket(port);
            connectionSocket = welcomeSocket.accept();
            fromClient = new DataInputStream(connectionSocket.getInputStream());
            toClient = new DataOutputStream(connectionSocket.getOutputStream());

            while (!connectionSocket.isClosed()) {

                int packetType = fromClient.readInt();
                //	TODO: 	Print the packetType
                System.out.println("Packet type: "+packetType);


                //If the packet is proving the identity of server
                if (packetType == 2){
                    //M = Hello this is Secstore using Ks- (private key)
                    // Hello, this is SecStore should be encrypted with private key
                    //encryption using private key
                    byte[] encryptedBytesArray = rsa.encrypt(fromClient.readUTF(), privateKey);
                    //encrypted message
                    String encrypted_string_m = Base64.getEncoder().encodeToString(encryptedBytesArray);
                    //reply the encrypted string M to client
                    toClient.writeUTF(encrypted_string_m);

                }

                //requested for certification, certificate request = 3
                if (packetType == 3){
                    //send the signed certificate to the client
                    //we can't pass in certificate crt format, hence, need to encode it into string, then, send to the client
                    byte[] certifByte = x509Certificate.getEncoded();
                    String certif = Base64.getEncoder().encodeToString(certifByte);
                    toClient.writeUTF(certif);

                }

                // If the packet is for transferring the filename
                if (packetType == 0) {

                    System.out.println("Receiving file...");

                    int numBytes = fromClient.readInt();
                    byte [] filename = new byte[numBytes];

                    fromClient.readFully(filename, 0, numBytes);

                    fileOutputStream = new FileOutputStream("recv_"+new String(filename, 0, numBytes));
                    bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

                    // If the packet is for transferring a chunk of the file
                } else if (packetType == 1) {

                    int numBytes = fromClient.readInt();
                    byte [] block = new byte[numBytes];
                    fromClient.readFully(block, 0, numBytes);

                    if (numBytes > 0)
                        bufferedFileOutputStream.write(block, 0, numBytes);

                    if (numBytes < 117) {
                        System.out.println("Closing connection...");

                        if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
                        if (bufferedFileOutputStream != null) fileOutputStream.close();
                        fromClient.close();
                        toClient.close();
                        connectionSocket.close();
                    }
                }

            }
        } catch (Exception e) {e.printStackTrace();}




    }
}

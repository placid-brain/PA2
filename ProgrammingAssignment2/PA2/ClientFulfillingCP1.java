package com.company.cse;

import java.io.*;
import java.net.Socket;
import java.security.Key;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.PublicKey;
import java.util.Base64;
import java.security.cert.CertificateFactory;

public class ClientFulfillingCP1{

    public static void main(String[] args) {

        RSAUtils rsa = new RSAUtils();


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
            String firstMessage = "Hello SecStore, please prove your identity";
            //pass the client's message to the server
            toServer.writeUTF(firstMessage);

            //receive the encrypted message from the server which is the proof of the identity of the server
            final String m = fromServer.readUTF();


            //request certificate signed by CA
            toServer.writeInt(3);

            //decrypt the signed certificate
            //receive the server's encrypted signed certificate in string format
            String signedCertFromServer = fromServer.readUTF();
            byte[] CertArray = Base64.getDecoder().decode(signedCertFromServer);

            //Convert the decoded Byte[] into certificate (decrypt the signed certificate)

            InputStream signed = new ByteArrayInputStream(CertArray);
            X509Certificate ServerCert = (X509Certificate) cf.generateCertificate(signed);
            //extract the public key of ServerCert (2nd step of  client)
            PublicKey serverPublicKey = ServerCert.getPublicKey();

            //compute ks+ {m}
            byte[] mArray = Base64.getDecoder().decode(m);
            String dataDecrypted = rsa.decrypt(mArray, serverPublicKey);


            //verification process
            try{
                ServerCert.checkValidity();
                ServerCert.verify(publicKey);
            }
            catch(Exception e){
                System.out.println("Invalid and unverified certificate.");
                clientSocket.close();
            }

            if (dataDecrypted.equals(firstMessage)){
                System.out.println("it's certified");
                System.out.println("args length : " + args.length);
                //filenames are in string[] args, hence, loop the args to get filenames
                for (int i = 0; i < args.length; i++){
                    //After the verification process, send the file

                    System.out.println("Sending file...");

                    // Send the filename
                    toServer.writeInt(0); //writes zero
                    // this runs: System.out.println("Just sent 0");
                    toServer.writeInt(args[i].getBytes().length);
                    System.out.println("filename: " + args[i]);
                    toServer.write(args[i].getBytes());
                    toServer.flush();

                    // Open the file
                    fileInputStream = new FileInputStream(args[i]);
                    bufferedFileInputStream = new BufferedInputStream(fileInputStream);

                    byte[] fromFileBuffer = new byte[117];

                    // Send the file
                    for (boolean fileEnded = false; !fileEnded; ) {
                        numBytes = bufferedFileInputStream.read(fromFileBuffer);
                        fileEnded = numBytes < 117;

                        toServer.writeInt(1);
                        toServer.writeInt(numBytes);
                        //encrypt the file data before sending
                        //String fromFileBufferString = new String(fromFileBuffer, 0, numBytes);
                        //System.out.println("from file buffer string : "+fromFileBufferString);
                        byte[] encryptedFromFileBuffer = rsa.encrypt(new String(fromFileBuffer), serverPublicKey);
                        int encryptedNumBytes = encryptedFromFileBuffer.length;


                        //replace with encrypted numBytes
                        toServer.writeInt(encryptedNumBytes);
                        //replace with encrypted one

                        toServer.write(encryptedFromFileBuffer);
                        toServer.flush();
                    }
                    if (i == args.length - 1){
                        toServer.writeInt(200);
                        bufferedFileInputStream.close();
                        fileInputStream.close();
                    }
                }
                //close the file input stream at the end of the for loop

                System.out.println("Closing connection...");


            }else{
                //CHECK FAILED
                toServer.writeInt(100);
                System.out.println("Closing connection...");
                clientSocket.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }




        long timeTaken = System.nanoTime() - timeStarted;
        System.out.println("Program took: " + timeTaken / 1000000.0 + "ms to run");
    }

}

import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
//import java.security.cert.X509Certificate;
import java.security.PrivateKey;
public class ServerFulfillingAP {

	public static void main(String[] args) {
		//final X509Certificate x509certificate = CertificateReader.get("");
		//get private key since we need private key to sign a message and send that message to the client.
		//final PrivateKey privateKey = PrivateKeyReader.get("private_key.der");
		
		
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
				System.out.println(packetType);
				
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
				//	TODO:	Need to fix this for Authentication protocol
				
			}
		} catch (Exception e) {e.printStackTrace();}

		
	
	
	}
}

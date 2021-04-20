


import javax.crypto.*;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class AES {



    public static SecretKey genSessKey(int num) throws NoSuchAlgorithmException {

        //a random number is allocated to be session key
        //specifiying that a symmetric key from AES algorithm is needed
        KeyGenerator sessKey = KeyGenerator.getInstance("AES");
        sessKey.init(num);
        SecretKey key = sessKey.generateKey();
        return key;
    }

  public static void aesEncrypt(String algomode, SecretKey key, File input, File output) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        int processed_bytes;
        //specifying algorithm mode- which is AES
        Cipher cipher = Cipher.getInstance(algomode);

        //to signify encryption is taking place
        cipher.init(Cipher.ENCRYPT_MODE,key);

        //Files require input and output methods to compare intial and final stages
        FileInputStream f_input = new FileInputStream(input);
        FileOutputStream f_output= new FileOutputStream(output);

        //handout mentions CP2 uses large files
        //so segment the file into chunks that can be placed into arrays
        byte[] arr = new byte[64];
        //encryption starts
        while ((processed_bytes = f_input.read(arr)) != -1) {
            byte[] encrypted_arr = cipher.update(arr, 0, processed_bytes);
            if (encrypted_arr != null) {
                f_output.write(encrypted_arr);
            }
        }
        //final housekeeping for encryption
      byte[] final_encrypted_arr = new byte[0];
      try {
          final_encrypted_arr = cipher.doFinal();
      } catch (IllegalBlockSizeException e) {
          e.printStackTrace();
      } catch (BadPaddingException e) {
          e.printStackTrace();
      }
      if (final_encrypted_arr != null) {
            f_output.write(final_encrypted_arr);
        }

        f_input.close();
        f_output.close();
  }



    public static void aesDecrypt(String algomode, SecretKey key, File input, File output) throws IOException, BadPaddingException, IllegalBlockSizeException {
        int processed_bytes;
        //specifying algorithm mode- which is AES
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(algomode);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }

        //to signify decryption is taking place
        try {
            cipher.init(Cipher.DECRYPT_MODE,key);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        //Files require input and output methods to compare intial and final stages
        FileInputStream f_input = null;
        try {
            f_input = new FileInputStream(input);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        FileOutputStream f_output= null;
        try {
            f_output = new FileOutputStream(output);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        //handout mentions CP2 uses large files
        //so segment the file into chunks that can be placed into arrays
        byte[] arr = new byte[64];
        //decryption starts
        while ((processed_bytes = f_input.read(arr)) != -1) {
            byte[] decrypted_arr = cipher.update(arr, 0, processed_bytes);
            if (decrypted_arr != null) {
                f_output.write(decrypted_arr);
            }
        }
        //final housekeeping for decryption
        byte[] final_decrypted_arr = cipher.doFinal();
        if (final_decrypted_arr != null) {
            f_output.write(final_decrypted_arr);
        }

        f_input.close();
        f_output.close();
    }

    /*havent test out yet
    @Test

    void givenFile_whenEncrypt_thenSuccess() {

        SecretKey key = AES.genSessKey(128);
        String algorithm = "AES/ECB/PKCS5Padding";

        File resource = new FileInputStream("inputFile/baeldung.txt");
        File inputFile = resource.getFile();
        File encryptedFile = new File("classpath:baeldung.encrypted");
        File decryptedFile = new File("document.decrypted");
        AESUtil.encryptFile(algorithm, key, ivParameterSpec, inputFile, encryptedFile);
        AESUtil.decryptFile(
                algorithm, key, ivParameterSpec, encryptedFile, decryptedFile);
        assertThat(inputFile).hasSameTextualContentAs(decryptedFile);
    }

     */

}

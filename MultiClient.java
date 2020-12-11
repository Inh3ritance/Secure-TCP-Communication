import java.security.Provider;
import java.security.*;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.util.Scanner;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import javax.crypto.Cipher;

public class MultiClient{
  public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException {
    
    // Initialize Key Pair (Private + Public), RSA(512 bits)
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(512, new SecureRandom());
    KeyPair pair = keyGen.generateKeyPair();
    // Key Generated
    
    // Private key + Public Key
    PrivateKey rsa_private = pair.getPrivate();
    PublicKey rsa_public = pair.getPublic();
  
    // write public key for other client
    writePublicKey(rsa_public.getEncoded().toString());
    
    // Retrieve unique AES Key
    String secretKey = getKeyAES();
      
    // Perform and test AES encryption/decryption 
    String originalString = getMessage();
    String encryptedString = AES.encrypt(originalString, secretKey);
    String decryptedString = AES.decrypt(encryptedString, secretKey);
     
    System.out.println(originalString);
    System.out.println(encryptedString);
    System.out.println(decryptedString);
    //  Done...
    
    // Encrypt AES Key so we can safely send it to the other client
    String encryptedAES = "";
    try {
      encryptedAES = encryption(secretKey,rsa_private);
    } catch (Exception e) {
      e.printStackTrace();
    }
    
    // We now have Encrypte message and Encrypted Key, now we need MAC for Authentication
    Mac mac = Mac.getInstance("HmacSHA256");
    String macString = "";
    try {
      SecretKeySpec secretKeySpec = new SecretKeySpec(rsa_public.getEncoded().toString().getBytes(), originalString);
      mac.init(secretKeySpec); // HMAC initializes with the RSA public key
      byte[] bytes = originalString.getBytes();      
      byte[] macResult = mac.doFinal(bytes);
      macString = new String(macResult);
    } catch (Exception e) {
      e.printStackTrace();
    }
    System.out.println("Sending these 3 pieces of data:");
    System.out.println("Encrypted Message: " + encryptedString);
    System.out.println("Encrypted Key: " + encryptedAES);
    System.out.println("Mac hashed with PublicKey: " + macString);
    
    // We need to send the Data/Trasfer (Write File)
    FileWriter fw = new FileWriter("./TransferedData/data.txt");
    fw.write(rsa_public);
    fw.close();
    
  }
  
  
  
  
  // Write Public key to file
  public static void writePublicKey(String publicKey) {
    try {
      FileWriter myWriter = new FileWriter("public_key.txt");
      myWriter.write(publicKey);
      myWriter.close();
    } catch (IOException e) {
      System.out.println("An error occurred.");
      e.printStackTrace();
    }
  }
  
  // Retrieve AES Public Key
  public static String getKeyAES(){
    String secretKey = "";
    try {
      File myObj = new File("public_key.txt");
      Scanner myReader = new Scanner(myObj);
      while (myReader.hasNextLine()) {
        secretKey = myReader.nextLine();
      }
      myReader.close();
    } catch (FileNotFoundException e) {
      System.out.println("An error occurred.");
      e.printStackTrace();
    }
    return secretKey;
  }
  
  // Retrieve This Client Message
  public static String getMessage(){
    String message = "";
    try {
      File myObj = new File("message.txt");
      Scanner myReader = new Scanner(myObj);
      while (myReader.hasNextLine()) {
        message = myReader.nextLine();
      }
      myReader.close();
    } catch (FileNotFoundException e) {
      System.out.println("An error occurred.");
      e.printStackTrace();
    }
    return message;
  }
  
  // Encrypt with RSA
  public static String encryption(String plainText, PrivateKey privateKey) throws Exception { // orininally byts[][]
    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.ENCRYPT_MODE, privateKey);
    byte[] enc = cipher.doFinal(plainText.getBytes());
    return Base64.getEncoder().encodeToString(enc);
  }
  
  // Decrypt with RSA
  public static String decryption(byte[] cipherText, PublicKey publicKey) throws Exception { // originally byte[]
    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.DECRYPT_MODE, publicKey);
    byte[] result = cipher.doFinal(cipherText);
    return new String(result);
  }
}


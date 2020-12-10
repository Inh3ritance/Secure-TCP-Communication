import java.security.Provider;
import java.security.*;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.util.Scanner;

public class MultiClient{
  public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException {
    
    // Initialize Key Pair (Private + Public), RSA(512 bits)
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(512);
    // Key Generated
    
    // Private key
    String rsa_private = getPrivateKey(keyGen);
    
    // Public Key
    String rsa_public = getPublicKey(keyGen);
  
    // write public key for other client
    writePublicKey(rsa_public);
    
    // Retrieve client AES Key from other client
    String secretKey = getKey();
      
    // Perform and test AES encryption/decryption 
    String originalString = getMessage();
    String encryptedString = AES.encrypt(originalString, secretKey);
    String decryptedString = AES.decrypt(encryptedString, secretKey);
     
    System.out.println(originalString);
    System.out.println(encryptedString);
    System.out.println(decryptedString);
    //  Done...
    
    // Encrypt AES Key so we can safely send it it to the other client
    
    
    
    //
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
  
  // Retreive RSA Public Key
  public static String getPublicKey(KeyPairGenerator keyGen){
    byte[] publicKey = keyGen.genKeyPair().getPublic().getEncoded();
    StringBuffer retString = new StringBuffer();
    for (int i = 0; i < publicKey.length; ++i)
     retString.append(Integer.toHexString(0x0100 + (publicKey[i] & 0x00FF)).substring(1));
    return retString.toString();
  }
  
  // Retrieve RSA Private Key
  public static String getPrivateKey(KeyPairGenerator keyGen){
    byte[] publicKey = keyGen.genKeyPair().getPrivate().getEncoded();
    StringBuffer retString = new StringBuffer();
    for (int i = 0; i < publicKey.length; ++i)
     retString.append(Integer.toHexString(0x0100 + (publicKey[i] & 0x00FF)).substring(1));
    return retString.toString();
  }
  
  // Retrieve AES Public Key
  public static String getKey(){
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
  
}


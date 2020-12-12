import java.security.*;
import java.io.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.spec.*;
import java.nio.charset.Charset;
import java.nio.file.*;

public class ClientA {
  
  public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException {
    
    KeyPair p = null;
    if(keysMade()) {
      // Initialize Key Pair (Private + Public), RSA(512 bits), dynamic changing key
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
      keyGen.initialize(512, new SecureRandom());
      KeyPair pair = keyGen.generateKeyPair();
      p = pair;
    
      // write public key for other client to use
      writeKey(pair.getPublic().getEncoded(), "public.key");
      writeKey(pair.getPrivate().getEncoded(), "private.key"); 
    } else {
      p = getPair();
    }
    
    System.out.println("Are you the sender(y) or the reciever(n))");
    Scanner scan = new Scanner(System.in);
    String str = scan.nextLine();
    
    if(str.equals("y")) send();
    else recieve(p);
  }
  
  public static void recieve(KeyPair pair) {
    
    // Get data from transferedfiles/data.txt
    String encryptedMessage = "";
    String encryptedKey = "";
    String encryptedmac = "";
    try {
      BufferedReader br = new BufferedReader(new FileReader("../TransferedData/data.txt"));
      encryptedMessage = br.readLine();
      encryptedKey = br.readLine();
      encryptedmac = br.readLine();
      br.close();
    } catch (FileNotFoundException e) {
      e.printStackTrace();
    } catch(IOException e){
      e.printStackTrace();
    }
    
    //Display file data
    System.out.println(encryptedMessage);
    System.out.println(encryptedKey);
    System.out.println(encryptedmac);
    
    // Decrypt AES Key so we can decrypt message
    String decryptedKey = "ClientB_AES";
    
    /*try {
      decryptedKey = decryption(key, pair.getPrivate());
    } catch (Exception e) {
      e.printStackTrace();
    }*/
    
    // Decrypt message
     String decryptedString = AES.decrypt(encryptedMessage, decryptedKey);
    
    // verify with Mac
    String verify = "";
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      SecretKeySpec secretKeySpec = new SecretKeySpec(pair.getPublic().getEncoded(), decryptedString); // here
      mac.init(secretKeySpec);
      byte[] bytes = decryptedString.getBytes(Charset.forName("UTF-8"));      
      byte[] macResult = mac.doFinal(bytes);
      verify = new String(macResult);
    } catch (Exception e) {
      e.printStackTrace();
    }
    
     // Notify if verification is legit
    if(verify.length() == encryptedmac.length()){
      System.out.println("This message is authentic and not tampered with");
    } else {
      System.out.println("This message is not authentic, tampered with");
    }
    
    // Lets check the data
    System.out.println("recieved these 3 pieces of data:");
    System.out.println("Decrypted Message: " + decryptedString);
    System.out.println("Decrypted Key: " + decryptedKey);
    System.out.println("Mac hashed with PublicKey: " + verify);
    System.out.println("Mac from data file: " + encryptedmac);
    
  }
  
  public static void send(){

   // Load Key
    PublicKey rsa_public = loadPublicKey("../ClientB/public.key");
    
    // Retrieve unique AES Key
    String secretKey = "ClientA_AES";
      
    // Perform and test AES encryption/decryption 
    String originalString = getMessage();
    String encryptedString = AES.encrypt(originalString, secretKey);
    String decryptedString = AES.decrypt(encryptedString, secretKey);
    
    // Encrypt AES Key so we can safely send it to the other client
    String encryptedAES = "";
    try {
      encryptedAES = new String(encryption(secretKey,rsa_public));
    } catch (Exception e) {
      e.printStackTrace();
    }
    
    // We now have Encrypte message and Encrypted Key, now we need MAC for Authentication
    String macString = "";
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      SecretKeySpec secretKeySpec = new SecretKeySpec(rsa_public.getEncoded(), originalString); // here maybe
      mac.init(secretKeySpec); // HMAC initializes with the RSA public key
      byte[] bytes = originalString.getBytes(Charset.forName("UTF-8"));      
      byte[] macResult = mac.doFinal(bytes);
      macString = new String(macResult);
    } catch (Exception e) {
      e.printStackTrace();
    }
    
    // Lets check the data
    System.out.println("Sending these 3 pieces of data:");
    System.out.println("Encrypted Message: " + encryptedString);
    System.out.println("Encrypted Key: " + encryptedAES);
    System.out.println("Mac hashed with PublicKey: " + macString);
    
    // We need to send the Data/Trasfer (Write File)
    try {
      FileWriter fw = new FileWriter("../TransferedData/data.txt");
      fw.write(encryptedString + System.getProperty( "line.separator" ));
      fw.write(encryptedAES + System.getProperty( "line.separator" ));
      fw.write(macString);
      fw.close();
      
      try (FileOutputStream fos = new FileOutputStream("keybytes")) {
        fos.write(encryption(secretKey,rsa_public));
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
  
  
  /* Encrypt/Decrypt */
  
  // Encrypt with RSA
  public static byte[] encryption(String plainText, PublicKey publicKey) throws Exception {
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    byte[] enc = new byte[256];
    enc = cipher.doFinal(Base64.getUrlEncoder().encode(plainText.getBytes(Charset.forName("UTF-8"))));
    return enc;
  }
  
  // Decrypt with RSA
  public static String decryption(byte[] cipherText, PrivateKey privateKey) throws Exception {
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.DECRYPT_MODE, privateKey);
    byte[] result = cipher.doFinal(cipherText);
    return new String(result, Charset.forName("UTF-8"));
  }
  
  /* Encrypt/Decrypt */
  
  /* Read/Write to Files */
  
  // Write Public key to file
  public static void writeKey(byte[] key, String pub_priv) { 
    try {
      FileOutputStream myWriter = new FileOutputStream(pub_priv);
      X509EncodedKeySpec i = new X509EncodedKeySpec(key);
      myWriter.write(i.getEncoded());
      myWriter.close();
    } catch (IOException e) {
      System.out.println("An error occurred.");
      e.printStackTrace();
    }
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
  
  /* Read/Write to Files */
  
  /* Retrieve Keys */
  
  // Are keys already Made?
  public static boolean keysMade() {
      File file = new File("public_key.key");
      File file2 = new File("private_key.key");
      return !(file.length() == 0 && file2.length() == 0);
  }
  
  // Public Recieve Key From other Client
  public static PublicKey loadPublicKey(String path){
    try {
      File file = new File(path);
      FileInputStream fis = new FileInputStream(path);
      byte[] encodedPublicKey = new byte[(int) file.length()];
      fis.read(encodedPublicKey);
      fis.close();
      
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
      PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
      return publicKey;
      
    } catch (FileNotFoundException e) {
      e.printStackTrace();
    } catch (IOException e){
      e.printStackTrace();
    } catch(NoSuchAlgorithmException e){
      e.printStackTrace();
    } catch(InvalidKeySpecException e){
      e.printStackTrace();
    }
    return null;
  }
  
  // Gets local Key Pair( Public / Private )
  public static KeyPair getPair(){
    try {
      File file = new File("public.key");
      FileInputStream fis = new FileInputStream("public.key");
      byte[] encodedPublicKey = new byte[(int) file.length()];
      fis.read(encodedPublicKey);
      fis.close();
      
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
      PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
      
      file = new File("private.key");
      fis = new FileInputStream("private.key");
      byte[] encodedPrivateKey = new byte[(int) file.length()];
      fis.read(encodedPrivateKey);
      fis.close();
      
      PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
      PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
      
      return new KeyPair(publicKey, privateKey);
      
    } catch (FileNotFoundException e) {
      e.printStackTrace();
    } catch (IOException e){
      e.printStackTrace();
    } catch(NoSuchAlgorithmException e){
      e.printStackTrace();
    } catch(InvalidKeySpecException e){
      e.printStackTrace();
    }
    return null;
  }
  
  /* Retrieve Keys */
  
}


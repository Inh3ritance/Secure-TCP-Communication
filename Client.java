import java.io.File;
import java.io.FileNotFoundException;
import java.util.Scanner;

public class Client {
  private static String message = "";
  
  public static void main(){
    
    
  }
  
  public static String getMessage(){
    String message = "";
    try {
      File myObj = new File("message.txt");
      Scanner myReader = new Scanner(myObj);
      while (myReader.hasNextLine()) {
        message = myReader.nextLine();
        System.out.println(message);
      }
      myReader.close();
    } catch (FileNotFoundException e) {
      System.out.println("An error occurred.");
      e.printStackTrace();
    }
    return message;
  }
}
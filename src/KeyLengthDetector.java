import javax.crypto.Cipher;
import java.security.NoSuchAlgorithmException;

public class KeyLengthDetector {
  public static void main(String[] args) {
    int allowedKeyLength = 0;

    try {
      allowedKeyLength = Cipher.getMaxAllowedKeyLength("AES");
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }

    System.out.println("The allowed key length for AES is: " + allowedKeyLength);
  }
}

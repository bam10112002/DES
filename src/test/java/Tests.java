import org.example.cryptography.Cryptography;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Tests {
    @Test
    public void Test1() throws Exception {
        String key = "FGZSDWSD";
        String initVector = "AVBFDFERHJYTDVBS";
        String dataString = "Hello my name is Artemi.";
        Cryptography cryptography = new Cryptography(Cryptography.Algorithm.DES, Cryptography.Mode.OFB, key);

        String encrypted = new String(cryptography.encrypt(dataString.getBytes(), initVector.getBytes()));
        String decrypted = new String(cryptography.decrypt(encrypted.getBytes(), initVector.getBytes()));
        assertEquals(decrypted, dataString);
    }
    @Test
    public void Test2() throws Exception {
        String key = "ARTEMFGA";
        String initVector = "AVBFDFERHJYTDVBS";
        String dataString = "Lorem ipsum dolor sit amet, nou.";
        Cryptography cryptography = new Cryptography(Cryptography.Algorithm.DES, Cryptography.Mode.OFB, key);

        String encrypted = new String(cryptography.encrypt(dataString.getBytes(), initVector.getBytes()));
        String decrypted = new String(cryptography.decrypt(encrypted.getBytes(), initVector.getBytes()));
        assertEquals(decrypted, dataString);
    }
    @Test
    public void Test3() throws Exception {
        String key = "ARTEMFGA";
        String initVector = "AVBFDFERHJYTDVBS";
        String dataString = "Lorem ipsum dolor sit amet, nou.";
        Cryptography cryptography = new Cryptography(Cryptography.Algorithm.DES, Cryptography.Mode.ECB, key);

        String encrypted = new String(cryptography.encrypt(dataString.getBytes()));
        String decrypted = new String(cryptography.decrypt(encrypted.getBytes()));
        assertEquals(decrypted, dataString);
    }
}

import org.example.cryptography.Cryptography;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DESTest {
    @Test
    void ECBTest() throws Exception {
        String key = "ARTEMFGA";
        String dataString = "Lorem ipsum dolor sit amet, nou.";
        Cryptography cryptography = new Cryptography(Cryptography.Algorithm.DES, Cryptography.Mode.ECB, key);

        String encrypted = new String(cryptography.encrypt(dataString.getBytes()));
        String decrypted = new String(cryptography.decrypt(encrypted.getBytes()));
        assertEquals(decrypted, dataString);
    }
    @Test
    void CFBTest() throws Exception {
        String key = "ARTEMFGA";
        String initVector = "HJGSDURG";
        String dataString = "Lorem ipsum dolor sit amet, nou.";
        Cryptography cryptography = new Cryptography(Cryptography.Algorithm.DES, Cryptography.Mode.CFB, key);

        String encrypted = new String(cryptography.encrypt(dataString.getBytes(), initVector.getBytes()));
        String decrypted = new String(cryptography.decrypt(encrypted.getBytes(), initVector.getBytes()));
        assertEquals(decrypted, dataString);
    }
    @Test
    void OFBTest() throws Exception {
        String key = "ARTEMFGA";
        String initVector = "HJGSDURG";
        String dataString = "Lorem ipsum dolor sit amet, nou.";
        Cryptography cryptography = new Cryptography(Cryptography.Algorithm.DES, Cryptography.Mode.OFB, key);

        String encrypted = new String(cryptography.encrypt(dataString.getBytes(), initVector.getBytes()));
        String decrypted = new String(cryptography.decrypt(encrypted.getBytes(), initVector.getBytes()));
        assertEquals(decrypted, dataString);
    }

    @Test
    void RDTest() throws Exception {
        String key = "ARTEMFGA";
        String initVector = "HJGSDURGGKMVDYQC";
        String dataString = "Lorem ipsum dolor sit amet, nou.";
        Cryptography cryptography = new Cryptography(Cryptography.Algorithm.DES, Cryptography.Mode.RD, key);

        String encrypted = new String(cryptography.encrypt(dataString.getBytes(), initVector.getBytes()));
        String decrypted = new String(cryptography.decrypt(encrypted.getBytes(), initVector.getBytes()));
        assertEquals(decrypted, dataString);
    }
    @Test
    void CBCTest() throws Exception {
        String key = "ARTEMFGA";
        String initVector = "HJGSDURG";
        String dataString = "Integer ornare metus et posuere.";
        Cryptography cryptography = new Cryptography(Cryptography.Algorithm.DES, Cryptography.Mode.CBC, key);

        String encrypted = new String(cryptography.encrypt(dataString.getBytes(), initVector.getBytes()));
        String decrypted = new String(cryptography.decrypt(encrypted.getBytes(), initVector.getBytes()));
        assertEquals(decrypted, dataString);
    }
    @Test
    void CTRTest() throws Exception {
        String key = "ARTEMFGA";
        String initVector = "HJGSDURG";
        String dataString = "Lorem ipsum dolor sit amet, nou.";
        Cryptography cryptography = new Cryptography(Cryptography.Algorithm.DES, Cryptography.Mode.CTR, key);

        String encrypted = new String(cryptography.encrypt(dataString.getBytes(), initVector.getBytes()));
        String decrypted = new String(cryptography.decrypt(encrypted.getBytes(), initVector.getBytes()));
        assertEquals(decrypted, dataString);
    }
}

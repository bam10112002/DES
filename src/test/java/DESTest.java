import org.example.cryptography.Cryptography;
import org.example.cryptography.des.DES;
import org.example.cryptography.exceptions.XORException;
import org.example.cryptography.keys.DESKey;
import org.example.cryptography.keys.Key;
import org.example.cryptography.keys.KeyGenerator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DESTest {
    String dataString = "Hellomy.";
    Key key = KeyGenerator.generateKey(Cryptography.Algorithm.DES);

    @Test
    void OnlyDes() throws XORException {
        for(int i = 0; i < 100; i++) {
            key = KeyGenerator.generateKey(Cryptography.Algorithm.DES);
            DES des = new DES(((DESKey) key).getValue());
            String decripted = new String(des.decrypt(des.encrypt(dataString.getBytes())));
            assertEquals(decripted, dataString);
        }
    }
    @Test
    void ECBTest() throws Exception {
        Cryptography cryptography = new Cryptography(Cryptography.Algorithm.DES, Cryptography.Mode.ECB, key);
        String encrypted = new String(cryptography.encrypt(dataString.getBytes()));
        String decrypted = new String(cryptography.decrypt(encrypted.getBytes()));
        assertEquals(decrypted, dataString);
    }
    @Test
    void CFBTest() throws Exception {
//        var key = KeyGenerator.generateKey(Cryptography.Algorithm.DES);
        String initVector = "HJGSDURG";
        Cryptography cryptography = new Cryptography(Cryptography.Algorithm.DES, Cryptography.Mode.CFB, key);

        String encrypted = new String(cryptography.encrypt(dataString.getBytes(), initVector.getBytes()));
        String decrypted = new String(cryptography.decrypt(encrypted.getBytes(), initVector.getBytes()));
        assertEquals(decrypted, dataString);
    }
    @Test
    void OFBTest() throws Exception {
//        var key = KeyGenerator.generateKey(Cryptography.Algorithm.DES);
        String initVector = "HJGSDURG";
        Cryptography cryptography = new Cryptography(Cryptography.Algorithm.DES, Cryptography.Mode.OFB, key);

        String encrypted = new String(cryptography.encrypt(dataString.getBytes(), initVector.getBytes()));
        String decrypted = new String(cryptography.decrypt(encrypted.getBytes(), initVector.getBytes()));
        assertEquals(decrypted, dataString);
    }

    @Test
    void RDTest() throws Exception {
//        var key = KeyGenerator.generateKey(Cryptography.Algorithm.DES);
        String initVector = "HJGSDURGGKMVDYQC";
        Cryptography cryptography = new Cryptography(Cryptography.Algorithm.DES, Cryptography.Mode.RD, key);

        String encrypted = new String(cryptography.encrypt(dataString.getBytes(), initVector.getBytes()));
        String decrypted = new String(cryptography.decrypt(encrypted.getBytes(), initVector.getBytes()));
        assertEquals(decrypted, dataString);
    }
    @Test
    void CBCTest() throws Exception {
//        var key = KeyGenerator.generateKey(Cryptography.Algorithm.DES);
        String initVector = "HJGSDURG";
        Cryptography cryptography = new Cryptography(Cryptography.Algorithm.DES, Cryptography.Mode.CBC, key);

        String encrypted = new String(cryptography.encrypt(dataString.getBytes(), initVector.getBytes()));
        String decrypted = new String(cryptography.decrypt(encrypted.getBytes(), initVector.getBytes()));
        assertEquals(decrypted, dataString);
    }
    @Test
    void CTRTest() throws Exception {
//        var key = KeyGenerator.generateKey(Cryptography.Algorithm.DES);
        String initVector = "HJGSDURG";
        Cryptography cryptography = new Cryptography(Cryptography.Algorithm.DES, Cryptography.Mode.CTR, key);

        String encrypted = new String(cryptography.encrypt(dataString.getBytes(), initVector.getBytes()));
        String decrypted = new String(cryptography.decrypt(encrypted.getBytes(), initVector.getBytes()));
        assertEquals(decrypted, dataString);
    }
}

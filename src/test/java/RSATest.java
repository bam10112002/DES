import org.example.cryptography.rsa.RSA;
import org.example.cryptography.rsa.keys.KeyPair;
import org.example.cryptography.rsa.keys.RSAKeyGenerator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RSATest {
    @Test
    void Test1() throws InterruptedException {
//        long start = System.currentTimeMillis();
        String data = "Hello my name is Artem";
        RSAKeyGenerator gen = new RSAKeyGenerator();
        KeyPair keys = gen.generateKeyPair(1024*4);
        byte[] encripted = RSA.encript(data.getBytes(), keys);
        String decripted = new String(RSA.decript(encripted, keys));
        System.out.println(encripted);

        assertEquals(data, decripted);

    }
}

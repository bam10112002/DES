import org.example.cryptography.benaloh.Benaloh;
import org.example.cryptography.benaloh.BenalohKeyGenerator;
import org.example.cryptography.benaloh.BenalohKeyPair;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
class BenalohTests {
    BigInteger R = BigInteger.valueOf(1009);
    Benaloh benaloh = new Benaloh(R);
    BenalohKeyGenerator gen = new BenalohKeyGenerator();
    BenalohKeyPair keys = gen.keyGeneration(512, R);

    public BenalohTests() throws InterruptedException {
    }


    @ParameterizedTest
    @ValueSource(ints = {100, 323, 12, 0, 1, 1000})
    void Test1(int num) {
        BigInteger message= BigInteger.valueOf(num);

        BigInteger chipper = benaloh.encrypt(message, keys.getPublicKey());
        BigInteger decrypted = benaloh.decrypt(chipper, keys.getPrivateKey());

        assertEquals(message, decrypted);

    }

}

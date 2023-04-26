import org.example.cryptography.rsa.simplicityTests.*;
import org.junit.jupiter.api.Test;
import java.math.BigInteger;
import java.util.Random;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

public class SimplicityTest {
    BigInteger[] SimplicityNumbers = {new BigInteger("13"), new BigInteger("29"), new BigInteger("7"),
            new BigInteger("1000037"), new BigInteger("1000081"), new BigInteger("1000213"),
            new BigInteger("341111111111"), new BigInteger("11213")};
    BigInteger[] Numbers = {new BigInteger("2"), new BigInteger("16"), new BigInteger("1000"),
            new BigInteger("2560"), new BigInteger("100008")};

    @Test
    void SolovayStrassenTests() {
        SimplicityTestInterface test = new SolovayStrassenTest();
        for (BigInteger num : SimplicityNumbers) {
            assertEquals(test.check(num, 0.9999),true);
        }
        for (BigInteger num : Numbers) {
            assertEquals(test.check(num, 0.9999),false);;
        }
    }

    @Test
    void FarmTests() {
        SimplicityTestInterface test = new FarmTest();
        for (BigInteger num : SimplicityNumbers) {
            assertTrue(test.check(num, 0.9999));
        }
        for (BigInteger num : Numbers) {
            assertFalse(test.check(num, 0.9999));;
        }
    }

    @Test
    void MillerRabinTests() {
        SimplicityTestInterface test = new MillerRabinTest();
        for (BigInteger num : SimplicityNumbers) {
            assertTrue(test.check(num, 0.9999));
        }
        for (BigInteger num : Numbers) {
            assertFalse(test.check(num, 0.9999));;
        }
    }
}

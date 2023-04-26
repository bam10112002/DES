package org.example;


import org.example.cryptography.rsa.RSA;
import org.example.cryptography.rsa.keys.KeyPair;
import org.example.cryptography.rsa.keys.ParallelRSAKeyGenerator;

import java.math.BigInteger;


public class Main {
    public static void main(String[] args) throws InterruptedException {
        String data = "Hello my name is Artem";
        ParallelRSAKeyGenerator gen = new ParallelRSAKeyGenerator();
        for (int i = 0; i < 20; i++) {
            KeyPair keys = gen.generateKeyPair(1024 * 2);
        }
//        byte[] encripted = RSA.encript(data.getBytes(), keys);
//        String decripted = new String(RSA.decript(encripted, keys));
//        System.out.println(decripted);
    }

    public static BigInteger modPow(BigInteger a, BigInteger b, BigInteger mod){
        BigInteger res = BigInteger.ONE;
        BigInteger two = BigInteger.TWO;
        int len = b.bitLength();

        for (int i = len-1; i > 0; i--) {
            if (b.testBit(i))
                res = res.multiply(a);

            res = res.modPow(two, mod);
        }

        if (b.testBit(0))
            res = res.multiply(a);

        return res;
    }
}
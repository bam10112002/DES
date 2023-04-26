package org.example.cryptography.rsa;

import org.example.cryptography.rsa.keys.KeyPair;

import java.math.BigInteger;

public class RSA {
    public static byte[] encript(byte[] data, KeyPair pair) {
        if (data.length > pair.getPublicKey().length)
            return new byte[0];

        new BigInteger(pair.getPublicKey());
        return new BigInteger(data).modPow(new BigInteger(pair.getPublicKey()),
                new BigInteger(pair.getN())).toByteArray();
    }

    public static byte[] decript(byte[] data, KeyPair pair) {
        if (data.length > pair.getPublicKey().length)
            return new byte[0];

        new BigInteger(pair.getPublicKey());
        return new BigInteger(data).modPow(new BigInteger(pair.getPrivateKey()),
                new BigInteger(pair.getN())).toByteArray();
    }
}

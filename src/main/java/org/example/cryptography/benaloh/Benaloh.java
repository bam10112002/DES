package org.example.cryptography.benaloh;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class Benaloh {

    Random random = new SecureRandom();
    public BigInteger R;

    public Benaloh(BigInteger R) {
        this.R = R;
    }

    private BigInteger randomNumFromZ(BigInteger n) {
        BigInteger num;
        do {
            num = new BigInteger(n.bitLength(), random);
        } while (num.compareTo(n) >= 0 || !num.gcd(n).equals(BigInteger.ONE));
        return num;
    }

    public BigInteger encrypt(BigInteger data, BenalohPublicKey publicKey){
        BigInteger u = randomNumFromZ(publicKey.getN());
        BigInteger cipher1 = publicKey.getY().modPow(data, publicKey.getN());
        BigInteger cipher2 = u.modPow(this.R, publicKey.getN());

        return cipher1.multiply(cipher2).mod(publicKey.getN());
    }

    public BigInteger decrypt(BigInteger data, BenalohPrivateKey privateKey){
        BigInteger a = data.modPow(privateKey.getPhi().divide(this.R), privateKey.getN());

        BigInteger c;
        for(BigInteger i=BigInteger.ZERO; i.compareTo(R) < 0; i = i.add(BigInteger.ONE)) {
            c = privateKey.getX().modPow(i, privateKey.getN());
            if(a.equals(c))
                return i;
        }
        return BigInteger.valueOf(-1);
    }
}
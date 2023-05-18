package org.example.cryptography.benaloh;

import java.math.BigInteger;

public class BenalohPublicKey {
    private final BigInteger n;
    private final BigInteger y;

    public BenalohPublicKey(BigInteger n, BigInteger y) {
        this.n = n;
        this.y = y;
    }

    public BigInteger getN() {
        return n;
    }

    public BigInteger getY() {
        return y;
    }

}

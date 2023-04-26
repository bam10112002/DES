package org.example.cryptography.rsa.keys;

import lombok.Getter;

@Getter
public class KeyPair {
    byte[] publicKey;
    byte[] privateKey;
    byte[] n;

    public KeyPair(byte[] publicKey, byte[] privateKey, byte[] n) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.n = n;
    }
}

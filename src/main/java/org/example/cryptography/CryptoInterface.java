package org.example.cryptography;

import lombok.NonNull;
import org.example.cryptography.exceptions.XORException;

import java.nio.ByteBuffer;

public interface CryptoInterface {
    byte[] decrypt(byte[] data) throws Exception;
    byte[] encrypt(byte[] data) throws Exception;
    byte[] encrypt(@NonNull ByteBuffer data) throws XORException;
    byte[] decrypt(@NonNull ByteBuffer data) throws XORException;
}

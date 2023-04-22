package org.example.cryptography;

import java.nio.ByteBuffer;

public class CustomByteBuffer {
    private ByteBuffer buffer;
    private CustomByteBuffer(byte[] arr) {
        buffer = ByteBuffer.wrap(arr);
    }
    static CustomByteBuffer wrap(byte[] arr) {
        return new CustomByteBuffer(arr);
    }

    long getLong() { return buffer.getLong(); }
    void putLong(long value) { buffer.putLong(value); }

}
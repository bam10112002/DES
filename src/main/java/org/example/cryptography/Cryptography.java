package org.example.cryptography;

import com.google.common.primitives.Longs;
import lombok.NonNull;
import org.example.cryptography.des.DES;


import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

public class Cryptography {
    /**
     * DES (Data Encryption Standard) - блочный симметричный алгоритм шифрования
     */
    public enum Algorithm { DES}

    /**
     * ECB (Electronic Codebook) - каждый блок шифруется отдельно, не взаимодействуя с другими блоками
     *                             важно, что initVector не используется
     * CBC
     * CFB
     * OFB
     * CTR
     * RD
     *              важно, что initvector длинной 16 байт.
     */
    public enum Mode { ECB, CBC, CFB, OFB, CTR, RD }

    private static final int BLOCKLEN = 8;
    CryptoInterface algorithm;
    Mode mode;

    public Cryptography(@NonNull Algorithm algorithm, @NonNull Mode mode,
                        @NonNull String key) throws Exception {

        if (algorithm == Algorithm.DES) {
            this.algorithm = new DES(key);
        }
        this.mode = mode;
    }

    public byte @NonNull[] encrypt(byte @NonNull[] data) {
        if (Objects.requireNonNull(mode) == Mode.ECB) {
            return ecbEncrypt(data);
        }
        return new byte[0];
    }
    public byte @NonNull[] decrypt(byte @NonNull[] data) {
        if (Objects.requireNonNull(mode) == Mode.ECB) {
            return ecbDecrypt(data);
        }
        return new byte[0];
    }

    public byte @NonNull[] encrypt(byte @NonNull[] data, byte[] initialVector) {
        initialVector = Arrays.copyOf(initialVector, initialVector.length);
        switch (mode){
            case CBC -> { return cbcEncrypt(data, initialVector); }
            case CFB -> { return cfbEncrypt(data, initialVector); }
            case OFB -> { return ofbCrypt(data, initialVector); }
            case CTR -> { return ctrCrypt(data, initialVector); }
            case RD  -> { return rdCrypt(data, initialVector); }
            default -> { return new byte[0]; }
        }
    }
    public byte @NonNull[] decrypt(byte @NonNull[] data, byte[] initialVector) {
        initialVector = Arrays.copyOf(initialVector, initialVector.length);
        switch (mode){
            case CBC -> { return cbcDecrypt(data, initialVector); }
            case CFB -> { return cfbDecrypt(data, initialVector); }
            case OFB -> { return ofbCrypt(data, initialVector); }
            case CTR -> { return ctrCrypt(data, initialVector); }
            case RD  -> { return rdCrypt(data, initialVector); }
            default -> { return new byte[0]; }
        }
    }

    private byte[] ecbEncrypt(byte[] data) {
        try {
            return algorithm.encrypt(normalizeData(data,BLOCKLEN));
        } catch (Exception e) {
            return new byte[0];
        }
    }
    private byte[] ecbDecrypt(byte[] data) {
        try {
            return algorithm.decrypt(normalizeData(data,BLOCKLEN));
        } catch (Exception e) {
            return new byte[0];
        }
    }

    private byte @NonNull[] cbcEncrypt(byte @NonNull[] data,byte @NonNull[] initialVector) {
        // TODO: initVector must by len == BLOCKLEN.
        try {
            ByteBuffer buffer = normalizeData(data, BLOCKLEN);
            ByteBuffer resBuffer = ByteBuffer.allocate(buffer.limit());
            byte[] chunk = new byte[BLOCKLEN];

            while (buffer.position() != buffer.limit()) {
                buffer.get(chunk, 0, BLOCKLEN);
                chunk = algorithm.encrypt(xor(chunk, initialVector));
                resBuffer.put(chunk);
                initialVector = Arrays.copyOf(chunk,chunk.length);
            }
            return resBuffer.array();

        } catch (Exception e) {
            return new byte[0];
        }

    }
    private byte @NonNull [] cbcDecrypt(byte @NonNull[] data, byte @NonNull[] initialVector) {
        // TODO: initVector must by len == BLOCKLEN.
          try {
            ByteBuffer buffer = normalizeData(data, BLOCKLEN);
            // TODO: Выкинуть ошибку, такого быть не должно
            ByteBuffer resBuffer = ByteBuffer.allocate(buffer.limit());
            byte[] chunk = new byte[BLOCKLEN];

            while (buffer.position() != buffer.limit()) {
                buffer.get(chunk, 0, BLOCKLEN);
                resBuffer.put(xor(algorithm.decrypt(chunk), initialVector));
                initialVector = Arrays.copyOf(chunk,chunk.length);
            }

            return resBuffer.array();

        }
         catch (Exception e) {
            return new byte[0];
        }

    }

    private byte @NonNull[] cfbEncrypt(byte @NonNull[] data,byte @NonNull[] initialVector) {
        // TODO: initVector must by len == BLOCKLEN.
        try {
            ByteBuffer buffer = normalizeData(data, BLOCKLEN);
            ByteBuffer resBuffer = ByteBuffer.allocate(buffer.limit());
            byte[] chunk = new byte[BLOCKLEN];

            while (buffer.position() != buffer.limit()) {
                buffer.get(chunk, 0, BLOCKLEN);
                initialVector = xor(algorithm.encrypt(initialVector), chunk);
                resBuffer.put(initialVector);
            }
            return resBuffer.array();
        } catch (Exception e) {
            return new byte[0];
        }
    }
    private byte @NonNull[] cfbDecrypt(byte @NonNull[] data, byte @NonNull[] initialVector) {
        // TODO: initVector must by len == BLOCKLEN.
        try {
            ByteBuffer buffer = normalizeData(data, BLOCKLEN);
            ByteBuffer resBuffer = ByteBuffer.allocate(buffer.limit());
            byte[] chunk = new byte[BLOCKLEN];

            while (buffer.position() != buffer.limit()) {
                buffer.get(chunk, 0, BLOCKLEN);
                resBuffer.put(xor(algorithm.encrypt(initialVector), chunk));
                initialVector = Arrays.copyOf(chunk, chunk.length);
            }
            return resBuffer.array();
        } catch (Exception e) {
            return new byte[0];
        }
    }

    private byte @NonNull[] ofbCrypt(byte @NonNull[] data, byte @NonNull[] initialVector) {
        // TODO: initVector must by len == BLOCKLEN.
        try {
            byte[] chunk = new byte[BLOCKLEN];
            ByteBuffer buffer = normalizeData(data, BLOCKLEN);
            ByteBuffer resBuffer = ByteBuffer.allocate(buffer.limit());

            while (buffer.position() != buffer.limit()) {
                buffer.get(chunk, 0, BLOCKLEN);
                initialVector = algorithm.encrypt(initialVector);
                resBuffer.put(xor(initialVector, chunk));
            }
            return resBuffer.array();
        } catch (Exception e) {
            return new byte[0];
        }
    }

    private byte @NonNull[] ctrCrypt(byte @NonNull[] data, byte @NonNull[] startCounter) {
        // TODO: initVector must by len == BLOCKLEN.
        try {
            long counter = ByteBuffer.wrap(startCounter).position(0).getLong();
            byte[] chunk = new byte[BLOCKLEN];
            ByteBuffer buffer = normalizeData(data, BLOCKLEN);
            ByteBuffer resBuffer = ByteBuffer.allocate(buffer.limit());

            while (buffer.position() != buffer.limit()) {
                buffer.get(chunk, 0, BLOCKLEN);
                resBuffer.put(xor(algorithm.encrypt(Longs.toByteArray(counter)), chunk));
                counter++;
            }
            return resBuffer.array();
        } catch (Exception e) {
            return new byte[0];
        }
    }

    private byte @NonNull[] rdCrypt(byte @NonNull[] data,byte @NonNull[] initialVector) {
        //TODO: exception initVector must be lens of 16 byte.
        try {
            ByteBuffer init = ByteBuffer.wrap(initialVector).position(0);
            long counter = init.getLong();
            long delta = init.getLong();
            ByteBuffer buffer = normalizeData(data, BLOCKLEN);
            ByteBuffer resBuffer = ByteBuffer.allocate(buffer.limit());
            byte[] chunk = new byte[BLOCKLEN];

            while (buffer.position() != buffer.limit()) {
                buffer.get(chunk, 0, BLOCKLEN);
                resBuffer.put(xor(algorithm.encrypt(Longs.toByteArray(counter)), chunk));
                counter += delta;
            }
            return resBuffer.array();
        } catch (Exception e) {
            return new byte[0];
        }
    }

    /**
     * @param data массив байт для приведения к размеру кратному размеру блока
     * @param blockLen размер блока в байтах
     * @return нормализованная дата
     */
    private @NonNull ByteBuffer normalizeData(byte @NonNull[] data, int blockLen) {
        int targetLen = (int)Math.ceil(data.length*1.0/blockLen) * blockLen;
        ByteBuffer bytes = ByteBuffer.allocate(targetLen);
        bytes.put(data);
        if (data.length%8 != 0){
            for (int i = 0; i < 8 - data.length%8; i++) {
                bytes.put((byte) 0);
            }
        }
        return bytes.position(0);
    }

    private byte @NonNull[] xor(byte @NonNull[] left, byte @NonNull[] right) {
        if (left.length != right.length) { throw new ArrayIndexOutOfBoundsException(); }
        byte[] res = new byte[left.length];
        for (int i = 0; i < left.length; i++) {
            res[i] = (byte) (left[i] ^ right[i]);
        }
        return res;
    }
}

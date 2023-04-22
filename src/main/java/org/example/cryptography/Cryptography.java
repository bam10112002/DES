package org.example.cryptography;

import com.google.common.primitives.Longs;
import lombok.NonNull;
import org.example.cryptography.des.DES;
import org.example.cryptography.exceptions.KeyLenException;


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
     *              важно, что initVector длинной 16 байт.
     */
    public enum Mode { ECB, CBC, CFB, OFB, CTR, RD }

    private static final int BLOCKSIZE = 8;
    AlgorithmInterface algorithm;
    Mode mode;

    public Cryptography(@NonNull Algorithm algorithm, @NonNull Mode mode,
                        @NonNull String key) throws KeyLenException {

        if (algorithm == Algorithm.DES) {
            this.algorithm = new DES(key);
        }
        this.mode = mode;
    }

    public byte @NonNull[] encrypt(byte @NonNull[] data) {
        if (Objects.requireNonNull(mode) == Mode.ECB) {
            return ecbEncrypt(normalizeData(data));
        }
        return new byte[0];
    }
    public byte @NonNull[] decrypt(byte @NonNull[] data) {
        if (Objects.requireNonNull(mode) == Mode.ECB) {
            return ecbDecrypt(normalizeData(data));
        }
        return new byte[0];
    }

    public byte @NonNull[] encrypt(byte @NonNull[] data, byte[] initialVector) {
        initialVector = Arrays.copyOf(initialVector, initialVector.length);
        ByteBuffer normalizedData = normalizeData(data);
        switch (mode){
            case CBC -> { return cbcEncrypt(normalizedData, initialVector); }
            case CFB -> { return cfbEncrypt(normalizedData, initialVector); }
            case OFB -> { return ofbCrypt(normalizedData, initialVector); }
            case CTR -> { return ctrCrypt(normalizedData, initialVector); }
            case RD  -> { return rdCrypt(normalizedData, initialVector); }
            default -> { return new byte[0]; }
        }
    }
    public byte @NonNull[] decrypt(byte @NonNull[] data, byte[] initialVector) {
        initialVector = Arrays.copyOf(initialVector, initialVector.length);
        ByteBuffer convertedData = ByteBuffer.wrap(data);
        switch (mode){
            case CBC -> { return cbcDecrypt(convertedData, initialVector); }
            case CFB -> { return cfbDecrypt(convertedData, initialVector); }
            case OFB -> { return ofbCrypt(convertedData, initialVector); }
            case CTR -> { return ctrCrypt(convertedData, initialVector); }
            case RD  -> { return rdCrypt(convertedData, initialVector); }
            default -> { return new byte[0]; }
        }
    }

    private byte @NonNull[] ecbEncrypt(@NonNull ByteBuffer data) {
        try {
            return algorithm.encrypt(data);
        } catch (Exception e) {
            return new byte[0];
        }
    }
    private byte @NonNull[] ecbDecrypt(@NonNull ByteBuffer data) {
        try {
            return algorithm.decrypt(data);
        } catch (Exception e) {
            return new byte[0];
        }
    }

    private byte @NonNull[] cbcEncrypt(@NonNull ByteBuffer data, byte @NonNull[] initialVector) {
        // TODO: initVector must by len == BLOCKLEN.
        try {
            ByteBuffer resBuffer = ByteBuffer.allocate(data.limit());
            byte[] chunk = new byte[BLOCKSIZE];

            while (data.position() != data.limit()) {
                data.get(chunk, 0, BLOCKSIZE);
                chunk = algorithm.encrypt(xor(chunk, initialVector));
                resBuffer.put(chunk);
                initialVector = Arrays.copyOf(chunk,chunk.length);
            }
            return resBuffer.array();

        } catch (Exception e) {
            return new byte[0];
        }

    }
    private byte @NonNull [] cbcDecrypt(@NonNull ByteBuffer data, byte @NonNull[] initialVector) {
        // TODO: initVector must by len == BLOCKLEN.
          try {
            // TODO: Выкинуть ошибку, такого быть не должно
            ByteBuffer resBuffer = ByteBuffer.allocate(data.limit());
            byte[] chunk = new byte[BLOCKSIZE];

            while (data.position() != data.limit()) {
                data.get(chunk, 0, BLOCKSIZE);
                resBuffer.put(xor(algorithm.decrypt(chunk), initialVector));
                initialVector = Arrays.copyOf(chunk,chunk.length);
            }

            return resBuffer.array();

        }
         catch (Exception e) {
            return new byte[0];
        }

    }

    private byte @NonNull[] cfbEncrypt(@NonNull ByteBuffer data, byte @NonNull[] initialVector) {
        // TODO: initVector must by len == BLOCKLEN.
        try {
            ByteBuffer resBuffer = ByteBuffer.allocate(data.limit());
            byte[] chunk = new byte[BLOCKSIZE];

            while (data.position() != data.limit()) {
                data.get(chunk, 0, BLOCKSIZE);
                initialVector = xor(algorithm.encrypt(initialVector), chunk);
                resBuffer.put(initialVector);
            }
            return resBuffer.array();
        } catch (Exception e) {
            return new byte[0];
        }
    }
    private byte @NonNull[] cfbDecrypt(@NonNull ByteBuffer data, byte @NonNull[] initialVector) {
        // TODO: initVector must by len == BLOCKLEN.
        try {
            ByteBuffer resBuffer = ByteBuffer.allocate(data.limit());
            byte[] chunk = new byte[BLOCKSIZE];

            while (data.position() != data.limit()) {
                data.get(chunk, 0, BLOCKSIZE);
                resBuffer.put(xor(algorithm.encrypt(initialVector), chunk));
                initialVector = Arrays.copyOf(chunk, chunk.length);
            }
            return resBuffer.array();
        } catch (Exception e) {
            return new byte[0];
        }
    }

    private byte @NonNull[] ofbCrypt(@NonNull ByteBuffer data, byte @NonNull[] initialVector) {
        // TODO: initVector must by len == BLOCKLEN.
        try {
            byte[] chunk = new byte[BLOCKSIZE];
            ByteBuffer resBuffer = ByteBuffer.allocate(data.limit());

            while (data.position() != data.limit()) {
                data.get(chunk, 0, BLOCKSIZE);
                initialVector = algorithm.encrypt(initialVector);
                resBuffer.put(xor(initialVector, chunk));
            }
            return resBuffer.array();
        } catch (Exception e) {
            return new byte[0];
        }
    }

    private byte @NonNull[] ctrCrypt(@NonNull ByteBuffer data, byte @NonNull[] startCounter) {
        // TODO: initVector must by len == BLOCKLEN.
        try {
            long counter = ByteBuffer.wrap(startCounter).position(0).getLong();
            byte[] chunk = new byte[BLOCKSIZE];
            ByteBuffer resBuffer = ByteBuffer.allocate(data.limit());

            while (data.position() != data.limit()) {
                data.get(chunk, 0, BLOCKSIZE);
                resBuffer.put(xor(algorithm.encrypt(Longs.toByteArray(counter)), chunk));
                counter++;
            }
            return resBuffer.array();
        } catch (Exception e) {
            return new byte[0];
        }
    }

    private byte @NonNull[] rdCrypt(@NonNull ByteBuffer data, byte @NonNull[] initialVector) {
        //TODO: exception initVector must be lens of 16 byte.
        try {
            ByteBuffer init = ByteBuffer.wrap(initialVector).position(0);
            long counter = init.getLong();
            long delta = init.getLong();
            ByteBuffer resBuffer = ByteBuffer.allocate(data.limit());
            byte[] chunk = new byte[BLOCKSIZE];

            while (data.position() != data.limit()) {
                data.get(chunk, 0, BLOCKSIZE);
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
     * @return нормализованная дата
     */
    private @NonNull ByteBuffer normalizeData(byte @NonNull[] data) {
        int targetLen = (int)Math.ceil(data.length*1.0/ BLOCKSIZE) * BLOCKSIZE;
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

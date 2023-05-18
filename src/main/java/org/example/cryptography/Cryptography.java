package org.example.cryptography;

import com.google.common.primitives.Longs;
import lombok.NonNull;
import org.example.cryptography.des.DES;
import org.example.cryptography.exceptions.KeyLenException;
import org.example.cryptography.keys.DESKey;
import org.example.cryptography.keys.Key;
import org.example.cryptography.rsa.RSA;
import org.example.cryptography.rsa.keys.KeyPair;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;
import java.util.stream.IntStream;

public class Cryptography {
    /**
     * DES (Data Encryption Standard) - блочный симметричный алгоритм шифрования
     */
    public enum Algorithm { DES, RSA, TWOFISH}

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

    private int BLOCKSIZE = 8;
    Algorithm alg;
    AlgorithmInterface algorithm;
    Mode mode;

    public Cryptography(@NonNull Algorithm algorithm, @NonNull Mode mode,
                        @NonNull Key key) throws KeyLenException {

        switch (algorithm) {
            case DES -> this.algorithm = new DES(((DESKey)key).getValue());
            case TWOFISH -> {

            }
            case RSA -> {
                this.algorithm = new RSA((KeyPair)key);
                BLOCKSIZE = ((KeyPair)key).getN().length-1;
            }
        }
        this.mode = mode;
        alg = algorithm;
    }

    public byte @NonNull[] encrypt(byte @NonNull[] data) {
        ByteBuffer normalizedData;
        if (alg == Algorithm.DES)
            normalizedData = normalizeData(data);
        else
            normalizedData = ByteBuffer.wrap(data);

        if (Objects.requireNonNull(mode) == Mode.ECB) {
            return ecbEncrypt(normalizedData);
        }
        return new byte[0];
    }
    public byte @NonNull[] decrypt(byte @NonNull[] data) {
        if (alg == Algorithm.DES) {

        }

        if (Objects.requireNonNull(mode) == Mode.ECB) {
            return denormalizeData(ecbDecrypt(ByteBuffer.wrap(data)));
        }
        return new byte[0];
    }

    public byte @NonNull[] encrypt(byte @NonNull[] data, byte[] initialVector) {
        initialVector = Arrays.copyOf(initialVector, initialVector.length);
        ByteBuffer normalizedData;
        if (alg == Algorithm.DES)
            normalizedData = normalizeData(data);
        else
            normalizedData = ByteBuffer.wrap(data);

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
        byte[] res;
        switch (mode){
            case CBC -> { res = cbcDecrypt(convertedData, initialVector); }
            case CFB -> { res =  cfbDecrypt(convertedData, initialVector); }
            case OFB -> { res =  ofbCrypt(convertedData, initialVector); }
            case CTR -> { res =  ctrCrypt(convertedData, initialVector); }
            case RD  -> { res =  rdCrypt(convertedData, initialVector); }
            default -> { return new byte[0]; }
        }
        return denormalizeData(res);
    }

    private byte @NonNull[] ecbEncrypt(@NonNull ByteBuffer data) {
        try {
            ByteBuffer resBuffer = ByteBuffer.allocate(data.limit());
            byte[] chunk = new byte[BLOCKSIZE];

            while (data.position() != data.limit()) {
                data.get(chunk, 0, BLOCKSIZE);
                resBuffer.put(algorithm.encrypt(chunk));
            }
            return resBuffer.array();

        } catch (Exception e) {
            return new byte[0];
        }
    }
    private byte @NonNull[] ecbDecrypt(@NonNull ByteBuffer data) {
        try {
            ByteBuffer resBuffer = ByteBuffer.allocate(data.limit());
            byte[] chunk = new byte[BLOCKSIZE];

            while (data.position() != data.limit()) {
                data.get(chunk, 0, BLOCKSIZE);
                resBuffer.put(algorithm.decrypt(chunk));
            }
            return resBuffer.array();

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

    private byte @NonNull[] denormalizeData(byte[] arr) {
        int lastIndex = arr.length - 1;
        while (lastIndex >= 0 && arr[lastIndex] == 0) {
            lastIndex--;
        }
        byte[] resultArray = new byte[lastIndex + 1];
        System.arraycopy(arr, 0, resultArray, 0, lastIndex + 1);
        return resultArray;
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

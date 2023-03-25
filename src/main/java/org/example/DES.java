package org.example;

import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;

public class DES {
    private final CustomBitSet key;
    private CustomBitSet[] roundKeys;
    public DES(long key) throws Exception {
        this.key = normalizeKey(key);
        this.roundKeys = generateRoundKeys(this.key);
    }
    public DES(@NonNull String key) throws Exception {
        if (key.getBytes().length != 8)
            throw new Exception("key len must be = 64 bit");

        this.key = normalizeKey(stringToLong(key));
        this.roundKeys = generateRoundKeys(this.key);
    }

    public @NonNull CustomBitSet encrypt(@NonNull CustomBitSet bits) throws Exception {
        bits = transformation(bits, Matrices.getIp());
        CustomBitSet[] pair = bits.split(2);
        CustomBitSet left = pair[0];
        CustomBitSet right = pair[1];
        for (int i = 0; i < 16; i++) {
            CustomBitSet tmp = new CustomBitSet(left);
            left = new CustomBitSet(right);
            right = new CustomBitSet(tmp.xor(f(right, roundKeys[i])));
        }
        left = left.concat(right);
        return transformation(left, Matrices.getIp_1());
    }

    public @NonNull String encrypt(@NonNull String str) throws Exception {
        StringBuilder res = new StringBuilder();
        if (str.length()%8 != 0)
            str = StringUtils.rightPad(str,8 - str.length()%8 + str.length(), ' ');
        for (int i = 0 ; i < str.length()/8; i++) {
            CustomBitSet bits = new CustomBitSet(stringToLong(str.substring(i*8, (i+1)*8)));
            res.append(encrypt(bits).toUTF8String());
        }
        return res.toString();
    }

    public @NonNull String decrypt(@NonNull String str) throws Exception {
        StringBuilder res = new StringBuilder();
        if (str.length()%8 != 0)
            str = StringUtils.rightPad(str,8 - str.length()%8 + str.length(), ' ');
        for (int i = 0 ; i < str.length()/8; i++) {
            CustomBitSet bits = new CustomBitSet(stringToLong(str.substring(i*8, (i+1)*8)));
            res.append(decrypt(bits).toUTF8String());
        }
        return res.toString();
    }

    public @NonNull CustomBitSet decrypt(@NonNull CustomBitSet bits) throws Exception {
        bits = transformation(bits, Matrices.getIp());
        CustomBitSet[] pair = bits.split(2);
        CustomBitSet left = pair[0];
        CustomBitSet right = pair[1];
        for (int i = 15; i >= 0; i--) {
            CustomBitSet tmp = new CustomBitSet(left);
            left = new CustomBitSet(right);
            right = new CustomBitSet(tmp.xor(f(right, roundKeys[i])));
        }
        left = left.concat(right);
        return transformation(left, Matrices.getIp_1());
    }

    private @NonNull CustomBitSet normalizeKey(long key) {
        CustomBitSet oldKey = new CustomBitSet(key);
        CustomBitSet newKey = new CustomBitSet();
        newKey.setLen(56);
        for (int i = 0; i < 8; i++) {
            for (int j = 1; j <= 7; j++) {
                newKey.set((i*8+j)-i, oldKey.get(i*8+j));
            }
        }
        return newKey;
    }

    private @NonNull CustomBitSet[] generateRoundKeys(@NonNull CustomBitSet key) throws Exception {
        if (key.getLen() != 56)
            throw new Exception("The key length must be 56 bits");

        key = transformation(key, Matrices.getPc1());
        CustomBitSet[] lrKeys = key.split(2);
        CustomBitSet[] roundKeysMassive = new CustomBitSet[16];

        for (int round = 0; round < 16; round++) {
            lrKeys[0].leftShift(Matrices.getShiftBits()[round]);
            lrKeys[1].leftShift(Matrices.getShiftBits()[round]);
            roundKeysMassive[round] = transformation(lrKeys[0].concat(lrKeys[1]), Matrices.getPc_2());
        }

        return roundKeysMassive;
    }

    private @NonNull CustomBitSet transformation(@NonNull CustomBitSet bitSet, @NonNull byte[] transformationMatrix) {
        CustomBitSet newBits = new CustomBitSet();
        for (int i = 1; i <= transformationMatrix.length; i++)
            newBits.set(i, bitSet.get(transformationMatrix[i-1]));
        newBits.setLen(transformationMatrix.length);
        return newBits;
    }

    private @NonNull CustomBitSet f(@NonNull CustomBitSet bits, CustomBitSet roundKey) throws Exception {
        bits = transformation(bits, Matrices.getE());
        bits = bits.xor(roundKey);
        CustomBitSet[] sMatrix = bits.split(8);
        CustomBitSet res = new CustomBitSet(0,0);
        for (int i = 0; i < 8; i++) {
            CustomBitSet row = new CustomBitSet(new boolean[] {sMatrix[i].get(5), sMatrix[i].get(0)});
            CustomBitSet column = new CustomBitSet(new boolean[] {sMatrix[i].get(4), sMatrix[i].get(3),
                                                                sMatrix[i].get(2), sMatrix[i].get(1)});
            res = res.concat(new CustomBitSet(Matrices.getS_BOX()[i][(int) row.getData()][(int) column.getData()],4 ));
        }
        return transformation(res, Matrices.getP());
    }

    private long stringToLong(@NonNull String str) {
        long value = 0L;
        for (byte b : str.getBytes())
            value = (value << 8) + (b & 255);
        return value;
    }
}

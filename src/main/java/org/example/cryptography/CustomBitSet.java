package org.example.cryptography;


import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;
import org.example.cryptography.exceptions.XORException;

import java.nio.ByteBuffer;
import java.util.Objects;

/**
 * Класс, предназначенный для удобного доступа к битовым операциям над числом
 */
public class CustomBitSet {
    @Getter
    @Setter
    private long data;
    @Setter
    @Getter
    private int len;

    public CustomBitSet() {
        this.len = 64;
        this.data = 0;
    }
    public CustomBitSet(long data) {
        this.len = 64;
        this.data = data;
    }
    public CustomBitSet(long data, int len) {
        this(data);
        this.len = len;
    }

    public CustomBitSet(@NonNull String str) {
        // String to long
        len = str.length()*8;
        long data = 0L;
        for (byte b : str.getBytes())
            data = (data << 8) + (b & 255);
        System.out.println(data);
    }

    public @NonNull CustomBitSet(@NonNull boolean[] bites) {
        this(0,bites.length);
        for(int i = 0; i < bites.length; i++)
            set(i, bites[i]);
    }

    public CustomBitSet(@NonNull CustomBitSet bitSet) {
        data = bitSet.data;
        len = bitSet.len;
    }

    public void leftShift(int k) {
        data = (data << k) | (data >>> (len - k));
        data = data << len >>> len;
    }
//    public void rightShift(int k) {
//        data = (data >> k) | (data << (len - k));
//    }

    public void set(int ind, boolean bite) {
        if (bite) {
            data = data | (1L << ind-1);
        }
        else {
            data = data & ~(1L << ind-1);
        }
    }
    public boolean get(int ind) {
        return ((data >>> ind-1) & 1L) != 0;
    }

    /**
     * @param crushing на сколько частей необходимо разделить исходный массив
     * @return - массив
     */
    public @NonNull CustomBitSet[] split(int crushing) {
        int totalLen = len/crushing;
        CustomBitSet[] resMassive = new CustomBitSet[crushing];
        for (int i = 0; i < crushing; i++) {
            resMassive[i] = new CustomBitSet((data << i * totalLen) >>> len-totalLen, totalLen);
        }
        return resMassive;
    }

    public @NonNull CustomBitSet xor(@NonNull CustomBitSet bits) throws XORException {
        if (len != bits.len)
            throw new XORException(len, bits.len);

        return new CustomBitSet(data^bits.data, len);
    }

    /**
     * Метод отвечающий за объединение двух CustomBitSet
     * Пример: 101.concat(011) = 101011
     * @param bitSet правая половина для объединения двух CustomBitSet
     * @return обединение двух CustomBitSet
     */
    public @NonNull CustomBitSet concat(@NonNull CustomBitSet bitSet) {
        if (len == 0)
            return new CustomBitSet(bitSet);

        return new CustomBitSet(data | (bitSet.data << len), len + bitSet.len);
    }

    public String toUTF8String() {
        StringBuilder res = new StringBuilder();
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(data);
        for (int i = 0; i < 8; i++) {
            res.append((char)buffer.get(i));
        }
        return res.toString();
    }
    @Override
    public String toString() {
       return StringUtils.leftPad(Long.toBinaryString(data), 64, '0').substring(0, len);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CustomBitSet that = (CustomBitSet) o;
        return data == that.data;
    }
    @Override
    public int hashCode() {
        return Objects.hash(data);
    }
}

package org.example;

import org.example.cryptography.Cryptography;
import org.example.cryptography.des.DES;

import java.nio.charset.StandardCharsets;

public class Main {
    public static void main(String[] args) throws Exception {
        String key = "FGZSDWSD";
        String initVector = "AVBFDFERHJYTDVBS";
        String dataString = "HelloIAm";

//        DES des = new DES(key);
//        System.out.println("Encrypted text: " + new String(des.encrypt(dataString.getBytes(StandardCharsets.UTF_8))));
//        System.out.println(new String(des.decrypt(des.encrypt(dataString.getBytes(StandardCharsets.UTF_8)))));

        Cryptography cryptography = new Cryptography(Cryptography.Algorithm.DES, Cryptography.Mode.RD, key);
        String encrypted = new String(cryptography.encrypt(dataString.getBytes(), initVector.getBytes()));
        String decrypted = new String(cryptography.decrypt(encrypted.getBytes(), initVector.getBytes()));
        System.out.println("Data      = " + dataString);
        System.out.println("Encrypted = " + encrypted);
        System.out.println("Decrypted = " + decrypted);
    }

//    public static void Test2() throws Exception {
//        String keyString = "FGZSDWSD";
//        String dataString = "HiMyName";
//
//        long data = 0L;
//        for (byte b : dataString.getBytes())
//            data = (data << 8) + (b & 255);
//
//        long key = 0L;
//        for (byte b : keyString.getBytes())
//            key = (key << 8) + (b & 255);
//
//        DES des = new DES(key);
//        CustomBitSet encrypted = des.encrypt(new CustomBitSet(data));
//        long decrypted = des.decrypt(encrypted).getData();
//        System.out.println("Log: input = " + data);
//        System.out.println("Log: encrypted = " + encrypted.getData());
//        System.out.println("Log: decrypted = " + decrypted);
//        System.out.println("Log value == decrypted is " + (data == decrypted));
//    }
//    public static void Test1() throws Exception {
//        DES des = new DES(126879297332579L);
//
//        long val = 984584832476599749L;
//        CustomBitSet encrypted = des.encrypt(new CustomBitSet(val));
//        long decrypted = des.decrypt(encrypted).getData();
//        System.out.println("Log: input = " + val);
//        System.out.println("Log: encrypted = " + encrypted.getData());
//        System.out.println("Log: decrypted = " + decrypted);
//        System.out.println("Log value == decrypted is " + (val == decrypted));
//    }
}
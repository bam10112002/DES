package org.example;

public class Main {
    public static void main(String[] args) throws Exception {
        Test2();
        String key = "FGZSDWSD";
        String dataString = "HiMyName";

        long value = 0L;
        for (byte b : dataString.getBytes())
            value = (value << 8) + (b & 255);

        DES des = new DES(key);
        System.out.println((des.decrypt(des.encrypt(dataString))));
    }

    public static void Test2() throws Exception {
        String keyString = "FGZSDWSD";
        String dataString = "HiMyName";

        long data = 0L;
        for (byte b : dataString.getBytes())
            data = (data << 8) + (b & 255);

        long key = 0L;
        for (byte b : keyString.getBytes())
            key = (key << 8) + (b & 255);

        DES des = new DES(key);
        CustomBitSet encrypted = des.encrypt(new CustomBitSet(data));
        long decrypted = des.decrypt(encrypted).getData();
        System.out.println("Log: input = " + data);
        System.out.println("Log: encrypted = " + encrypted.getData());
        System.out.println("Log: decrypted = " + decrypted);
        System.out.println("Log value == decrypted is " + (data == decrypted));
    }
    public static void Test1() throws Exception {
        DES des = new DES(126879297332579L);

        long val = 984584832476599749L;
        CustomBitSet encrypted = des.encrypt(new CustomBitSet(val));
        long decrypted = des.decrypt(encrypted).getData();
        System.out.println("Log: input = " + val);
        System.out.println("Log: encrypted = " + encrypted.getData());
        System.out.println("Log: decrypted = " + decrypted);
        System.out.println("Log value == decrypted is " + (val == decrypted));
    }
}
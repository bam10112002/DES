package org.example.web;

import org.checkerframework.checker.units.qual.C;
import org.example.cryptography.Cryptography;
import org.example.cryptography.benaloh.Benaloh;
import org.example.cryptography.benaloh.BenalohPublicKey;
import org.example.cryptography.exceptions.KeyLenException;
import org.example.cryptography.twofish.TwoFishKey;
import org.example.cryptography.twofish.TwoFishKeyGenerator;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.util.Scanner;

public class Client {
    ObjectOutputStream out;
    ObjectInputStream in;
    Cryptography cryptography;
    public Client() {
        try (Socket clientSocket = new Socket("localhost", 4444)) {
            out = new ObjectOutputStream(clientSocket.getOutputStream());
            in = new ObjectInputStream(clientSocket.getInputStream());

            BenalohPublicKey publicKey = (BenalohPublicKey) in.readObject();
            System.out.println("Public key is read");
            Benaloh benaloh = new Benaloh(BigInteger.valueOf(257L));
            TwoFishKey key = (TwoFishKey) TwoFishKeyGenerator.generateKey();
            var encryptedKey = benaloh.encrypt(key.getKey(), publicKey);
            out.writeObject(encryptedKey);
            System.out.println("send encrypted two fish key");

            cryptography = new Cryptography(Cryptography.Algorithm.TWOFISH, Cryptography.Mode.ECB, key);

            var reader = new ReaderMsg(in, cryptography);
            reader.start();
            String str = "";
            Scanner scanner = new Scanner(System.in);
            while (!str.equals("stop")) {
                str = scanner.nextLine();
                send(str);
            }
            in.close();
            out.close();
            reader.interrupt();

        } catch (IOException | KeyLenException | InvalidKeyException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }
    private void send(String msg) {
        try {
            out.writeObject(cryptography.encrypt(msg.getBytes()));
        } catch (IOException ignored) {}
    }
}

class ReaderMsg extends Thread {
    Cryptography cryptography;
    private final ObjectInputStream in;
    ReaderMsg(ObjectInputStream _in, Cryptography _cryptography) {
        in = _in;
        cryptography = _cryptography;
    }
    @Override
    public void run() {

        String str;
        try {
            while (true) {
                str = new String(cryptography.decrypt((byte[])in.readObject()));
                if (str.equals("stop"))
                    break;
                System.out.println(str);

            }
        } catch (IOException e) {

        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }
}

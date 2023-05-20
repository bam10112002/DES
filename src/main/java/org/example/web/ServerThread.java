package org.example.web;

import org.example.cryptography.Cryptography;
import org.example.cryptography.benaloh.Benaloh;
import org.example.cryptography.benaloh.BenalohKeyGenerator;
import org.example.cryptography.exceptions.KeyLenException;
import org.example.cryptography.twofish.TwoFishKey;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

class ServerThread extends Thread {
    private final ObjectInputStream in; // поток чтения из сокета
    private final ObjectOutputStream out; // поток записи в сокет
    Cryptography cryptography;
    List<ServerThread> clients;
    public ServerThread(Socket socket, List<ServerThread> clients ) throws IOException, InterruptedException, ClassNotFoundException, KeyLenException, InvalidKeyException {
        System.out.println("[LOG] Client Conected");
        this.clients = clients;
        out = new ObjectOutputStream(socket.getOutputStream());
        in = new ObjectInputStream(socket.getInputStream());
        Benaloh benaloh = new Benaloh(BigInteger.valueOf(257L));
        BenalohKeyGenerator benalohKeyGenerator = new BenalohKeyGenerator();
        var keys = benalohKeyGenerator.keyGeneration(256, BigInteger.valueOf(257L));
        out.writeObject(keys.getPublicKey());

        byte[][] encryptedTwoFishKey = (byte[][]) in.readObject();
        TwoFishKey key = new TwoFishKey(benaloh.decrypt(encryptedTwoFishKey, keys.getPrivateKey()));
        cryptography = new Cryptography(Cryptography.Algorithm.TWOFISH, Cryptography.Mode.ECB, key);
        System.out.println("[LOG] Initial ended");
        start();
    }
    @Override
    public void run() {
        String word;
        try {

            while (true) {
                word = read();
                if(word.equals("stop")) {
                    System.out.println("[LOG] Client Disconnected");
                    break;
                }

                for (var client : clients) {
                    if (!(client.equals(this)))
                        client.send(word);
                }
                System.out.println(word); // либо вывод в консоль
            }

        } catch (IOException | ClassNotFoundException e) {
            System.err.println(Arrays.toString(e.getStackTrace()));
        }
    }

    private String read() throws IOException, ClassNotFoundException {
        return new String(cryptography.decrypt((byte[])in.readObject()));
    }

    private void send(String msg) {
        try {
            out.writeObject(cryptography.encrypt(msg.getBytes()));
        } catch (IOException ignored) {}
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ServerThread that = (ServerThread) o;
        return in.equals(that.in) && out.equals(that.out) && cryptography.equals(that.cryptography) && clients.equals(that.clients);
    }

    @Override
    public int hashCode() {
        return Objects.hash(in, out, cryptography, clients);
    }
}


package org.example.web;

import org.example.cryptography.exceptions.KeyLenException;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.util.LinkedList;

public class Server {

    public static final int PORT = 4444;
    public static LinkedList<ServerThread> serverList = new LinkedList<>(); // список всех нитей

    public Server() throws IOException {
        ServerSocket server = new ServerSocket(PORT);
        try {
            while (true) {
                // Блокируется до возникновения нового соединения:
                Socket socket = server.accept();
                try {
                    serverList.add(new ServerThread(socket, serverList)); // добавить новое соединенние в список
                } catch (IOException e) {
                    // Если завершится неудачей, закрывается сокет,
                    // в противном случае, нить закроет его при завершении работы:
                    socket.close();
                } catch (KeyLenException e) {
                    throw new RuntimeException(e);
                } catch (InvalidKeyException e) {
                    throw new RuntimeException(e);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                } catch (ClassNotFoundException e) {
                    throw new RuntimeException(e);
                }
            }
        } finally {
            server.close();
        }
    }
}
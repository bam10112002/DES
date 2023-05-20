package org.example;

import org.example.web.Client;
import org.example.web.Server;

import java.io.*;
import java.util.Scanner;


public class Main {
    public static void main(String[] args) throws IOException {
        System.out.println("Input role");
        Scanner scanner = new Scanner(System.in);
        if (scanner.nextLine().equals("Server")) {
            new Server();
        }
        else {
            new Client();
        }

    }
}
package org.example;

import org.example.view.ClientView;
import java.io.IOException;
import java.util.Scanner;

public class Main {

    public static void main(String[] args)
    {
        ClientView clientView = new ClientView();
        Scanner scanner = new Scanner(System.in);
        try {
            clientView.start();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
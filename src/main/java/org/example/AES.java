package org.example;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Scanner;

public class AES {

    //Encryption And Decryption methods Reference from : https://www.baeldung.com/java-aes-encryption-decryption

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        int choice;

        do {
            System.out.println("\nMenu:");
            //FILENAME: text.txt
            System.out.println("1. Encrypt a File");
            System.out.println("2. Decrypt a File");
            System.out.println("3. Quit");
            System.out.print("Enter your choice: ");
            choice = scanner.nextInt();

            switch (choice) {
                case 1:
                    encryptFile();
                    break;
                case 2:
                    decryptFile();
                    break;
                case 3:
                    System.out.println("Exiting the application...");
                    break;
                default:
                    System.out.println("Invalid choice. Please try again.");
            }
        } while (choice != 3);
    }

    public static void encryptFile() throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter the filename to encrypt: ");
        String fileName = scanner.nextLine();

        Key key = generateRandomKey();
        System.out.println("Generated key: " + key);

        encrypt(key, fileName);

        System.out.println("File encrypted successfully. Encrypted data written to ciphertext.txt");
    }

    public static void decryptFile() throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter the filename to decrypt: ");
        String fileName = scanner.nextLine();

        System.out.print("Enter the decryption key: ");
        String keyString = scanner.nextLine();
        Key key = new SecretKeySpec(keyString.getBytes(), "AES");

        decrypt(key, fileName);

        System.out.println("File decrypted successfully. Decrypted data written to plaintext.txt");
    }

    public static void encrypt(Key key, String fileName) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        File inputFile = new File(fileName);
        File outputFile = new File("ciphertext.txt");

        FileInputStream inputStream = new FileInputStream(inputFile);
        FileOutputStream outputStream = new FileOutputStream(outputFile);

        byte[] buffer = new byte[64];
        int bytesRead;

        while ((bytesRead = inputStream.read(buffer)) != -1) {
            byte[] encryptedData = cipher.doFinal(buffer, 0, bytesRead);
            outputStream.write(encryptedData);
        }

        inputStream.close();
        outputStream.close();
    }

    public static void decrypt(Key key, String fileName) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);

        File inputFile = new File(fileName);
        File outputFile = new File("plaintext.txt");

        FileInputStream inputStream = new FileInputStream(inputFile);
        FileOutputStream outputStream = new FileOutputStream(outputFile);

        byte[] buffer = new byte[64];
        int bytesRead;

        while ((bytesRead = inputStream.read(buffer)) != -1) {
            byte[] decryptedData = cipher.doFinal(buffer, 0, bytesRead);
            outputStream.write(decryptedData);
        }

        inputStream.close();
        outputStream.close();
    }

    public static Key generateRandomKey() throws Exception {
        SecureRandom random = SecureRandom.getInstanceStrong();
        byte[] keyBytes = new byte[16];
        random.nextBytes(keyBytes);
        return new SecretKeySpec(keyBytes, "AES");
    }

}


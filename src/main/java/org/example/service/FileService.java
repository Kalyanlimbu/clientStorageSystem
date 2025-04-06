package org.example.service;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;

public class FileService {
    private static final String ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String SECRET_KEY_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int ITERATION_COUNT = 65536;
    private static final int KEY_LENGTH = 256;
    private static final String BASE_FILE_URL = "http://localhost:8080/file/";
    private static final String BASE_USER_URL = "http://localhost:8080/user/";
    private static final HttpClient client = HttpClient.newHttpClient();

    public void uploadFile(Scanner scanner, String username, String password) throws Exception {
        String filePath;
        Path path = null;
        boolean validPath = false;
        while (!validPath) {
            System.out.print("Please enter the file path: ");
            filePath = scanner.nextLine();
            path = Paths.get(filePath);
            if (Files.exists(path) && Files.isRegularFile(path) && Files.isReadable(path)) {
                validPath = true;
            } else {
                if (!Files.exists(path)) {
                    System.out.println("File not found at path: " + filePath);
                } else if (!Files.isRegularFile(path)) {
                    System.out.println("Path does not point to a regular file: " + filePath);
                } else if (!Files.isReadable(path)) {
                    System.out.println("File is not readable: " + filePath);
                }
                System.out.println("Please enter a valid file path: ");
            }
        }
        System.out.print("Please enter the file name: ");
        String filename = scanner.nextLine().trim();
        String checkFileNameUrl = BASE_FILE_URL + "checkFilenameForUser?filename=" +
                URLEncoder.encode(filename, StandardCharsets.UTF_8) +
                "&username=" + URLEncoder.encode(username, StandardCharsets.UTF_8);
        HttpResponse<String> nameResponse = getRequest(checkFileNameUrl);
        while (nameResponse.statusCode() == 400) {
            System.out.println("*******************************************************");
            System.out.println("The filename already exists, please enter another file name.");
            System.out.print("Please enter the file name: ");
            filename = scanner.nextLine().trim();
            checkFileNameUrl = BASE_FILE_URL + "checkFilenameForUser?filename=" +
                    URLEncoder.encode(filename, StandardCharsets.UTF_8) +
                    "&username=" + URLEncoder.encode(username, StandardCharsets.UTF_8);
            nameResponse = getRequest(checkFileNameUrl);
        }
        byte[] fileData = Files.readAllBytes(path);
        byte[] salt = generateRandomBytes(16);
        byte[] iv = generateRandomBytes(16);
        SecretKey secretKey = generateKeyFromPassword(password, salt);
        byte[] encryptedData = encrypt(fileData, secretKey, iv);
        // Combine metadata and binary data into a single byte[] payload
        byte[] usernameBytes = username.getBytes(StandardCharsets.UTF_8);
        byte[] filenameBytes = filename.getBytes(StandardCharsets.UTF_8);
        // Structure: [usernameLen][username][filenameLen][filename][salt][iv][encryptedDataLen][encryptedData]
        ByteArrayOutputStream payload = new ByteArrayOutputStream();
        // Write username length and data
        payload.write(intToBytes(usernameBytes.length));
        payload.write(usernameBytes);
        // Write filename length and data
        payload.write(intToBytes(filenameBytes.length));
        payload.write(filenameBytes);
        // Write salt (fixed 16 bytes)
        payload.write(salt);
        // Write iv (fixed 16 bytes)
        payload.write(iv);
        // Write encryptedData length and data
        payload.write(intToBytes(encryptedData.length));
        payload.write(encryptedData);
        // Send the request
        HttpResponse<String> response = postRequest(BASE_FILE_URL + "upload", payload.toByteArray());
        System.out.println(response.body());
    }

    public void downloadFile(Scanner scanner, String username, String password, String situation) throws Exception {
        // 1. Get filename to download
        scanner.nextLine();
        String ownerName = "";
        if(situation.equals("downloadSharedFile")){
            int i = 0;
            while(true){
                if(i == 3){
                    System.out.println("Ran out of try again. Going back to main menu");
                    return;
                }
                System.out.print("Enter the owner name of the file you want to download: ");
                ownerName = scanner.nextLine().trim();
                String checkUsername = BASE_USER_URL + URLEncoder.encode(ownerName, StandardCharsets.UTF_8) + "/check";
                HttpResponse<String> checkResponse = postRequest(checkUsername);
                if(checkResponse.statusCode() == 400) break;
                System.out.println("Please enter the correct username.");
                i++;
            }
        }
        //scanner.nextLine();
        String filename;
        int noOfTry = 0;
        while(true){
            if(noOfTry == 3){
                System.out.println("Ran out of try again. Going back to main menu");
                return;
            }
            System.out.print("Enter the filename you want to download: ");
            filename = scanner.nextLine().trim();
            if (filename.isEmpty()) {
                System.out.println("Filename cannot be empty. Please enter a valid filename.");
                noOfTry++;
                continue;
            }
            String checkFileNameUrl;
            if(situation.equals("downloadSharedFile")){
                checkFileNameUrl = BASE_FILE_URL + "checkFilenameForUser?filename=" +
                        URLEncoder.encode(filename, StandardCharsets.UTF_8) +
                        "&username=" + URLEncoder.encode(ownerName, StandardCharsets.UTF_8);
            }else {
                checkFileNameUrl = BASE_FILE_URL + "checkFilenameForUser?filename=" +
                        URLEncoder.encode(filename, StandardCharsets.UTF_8) +
                        "&username=" + URLEncoder.encode(username, StandardCharsets.UTF_8);
            }
            HttpResponse<String> nameResponse = getRequest(checkFileNameUrl);
            if(nameResponse.statusCode() == 400) break;
            System.out.println("The filename does not exist, please enter an existing file name to download.");
            noOfTry++;
        }
        // 2. Get destination directory (main directory, not full path)
        Path destinationDir;
        while (true) {
            System.out.print("Enter the destination directory to read the downloaded file: ");
            String dirPath = scanner.nextLine().trim();
            destinationDir = Paths.get(dirPath);
            if (Files.exists(destinationDir) && Files.isDirectory(destinationDir) && Files.isWritable(destinationDir)) {
                break;
            }
            System.out.println("Invalid directory. It must exist and be writable.");
        }
        // Construct full destination path using the original filename
        Path destinationPath = destinationDir.resolve(filename);
        // Check if file already exists
        if (Files.exists(destinationPath)) {
            System.out.print("File already exists at " + destinationPath + ". Overwrite? (yes/no): ");
            String overwrite = scanner.nextLine().trim().toLowerCase();
            if (!overwrite.equals("yes") && !overwrite.equals("y")) {
                System.out.println("Download cancelled.");
                return;
            }
        }
        // 3. Download file from server
        String downloadUrl;
        HttpResponse<byte[]> response;
        if(situation.equals("downloadSharedFile")){
            downloadUrl = BASE_FILE_URL + "download?filename=" +
                    URLEncoder.encode(filename, StandardCharsets.UTF_8) +
                    "&username=" + URLEncoder.encode(ownerName, StandardCharsets.UTF_8);
                    response = client.send(
                    HttpRequest.newBuilder()
                            .uri(URI.create(downloadUrl))
                            .GET()
                            .build(),
                    HttpResponse.BodyHandlers.ofByteArray()
                    );

        }else{
            downloadUrl = BASE_FILE_URL + "download?filename=" +
                    URLEncoder.encode(filename, StandardCharsets.UTF_8) +
                    "&username=" + URLEncoder.encode(username, StandardCharsets.UTF_8);
            response = client.send(
                    HttpRequest.newBuilder()
                            .uri(URI.create(downloadUrl))
                            .GET()
                            .build(),
                    HttpResponse.BodyHandlers.ofByteArray()
            );
        }
        if (response.statusCode() != 200) {
            System.out.println("Error downloading file: " + response.statusCode() + " - " + new String(response.body(), StandardCharsets.UTF_8));
            return;
        }
        // 4. Parse response payload: [salt][iv][encryptedDataLen][encryptedData]
        ByteArrayInputStream input = new ByteArrayInputStream(response.body());
        byte[] salt = readBytes(input, 16);
        byte[] iv = readBytes(input, 16);
        int encryptedDataLen = bytesToInt(readBytes(input, 4));
        byte[] encryptedData = readBytes(input, encryptedDataLen);
        // 5. Decrypt the file
        SecretKey secretKey = generateKeyFromPassword(password, salt);
        byte[] decryptedData = decrypt(encryptedData, secretKey, iv);
        // 6. Save to destination
        Files.write(destinationPath, decryptedData);
        System.out.println("File successfully downloaded to: " + destinationPath);
    }

    public void deleteFile(Scanner scanner, String username) throws IOException, InterruptedException {
        System.out.print("Enter the filename you want to delete: ");
        String filename = scanner.nextLine().trim();
        String checkFileNameUrl = BASE_FILE_URL + "checkFilenameForUser?filename=" +
                URLEncoder.encode(filename, StandardCharsets.UTF_8) +
                "&username=" + URLEncoder.encode(username, StandardCharsets.UTF_8);
        HttpResponse<String> nameResponse = getRequest(checkFileNameUrl);
        while (nameResponse.statusCode() == 200) {
            System.out.println("*******************************************************");
            System.out.println("The filename does not exists, please enter the right file name to delete.");
            System.out.print("Please enter the file name: ");
            filename = scanner.nextLine().trim();
            checkFileNameUrl = BASE_FILE_URL + "checkFilenameForUser?filename=" +
                    URLEncoder.encode(filename, StandardCharsets.UTF_8) +
                    "&username=" + URLEncoder.encode(username, StandardCharsets.UTF_8);
            nameResponse = getRequest(checkFileNameUrl);
        }
        String deleteFileUrl = BASE_FILE_URL + "delete?filename=" +
                URLEncoder.encode(filename, StandardCharsets.UTF_8) +
                "&username=" + URLEncoder.encode(username, StandardCharsets.UTF_8);
        HttpResponse<String> response = deleteRequest(deleteFileUrl);
        System.out.println("Response: " + response.body());
    }

    public void renameFile(Scanner scanner, String username) throws IOException, InterruptedException {
        System.out.print("Enter the filename you want to rename (spaces are allowed): ");
        String oldFilename = scanner.nextLine().trim();
        String checkFileNameUrl = BASE_FILE_URL + "checkFilenameForUser?filename=" +
                URLEncoder.encode(oldFilename, StandardCharsets.UTF_8) +
                "&username=" + URLEncoder.encode(username, StandardCharsets.UTF_8);
        HttpResponse<String> nameResponse = getRequest(checkFileNameUrl);
        while (nameResponse.statusCode() == 200) {
            System.out.println("*******************************************************");
            System.out.println("The filename does not exist, please enter an existing file name to rename.");
            System.out.print("Please enter the file name (spaces are allowed): ");
            oldFilename = scanner.nextLine().trim();
            checkFileNameUrl = BASE_FILE_URL + "checkFilenameForUser?filename=" +
                    URLEncoder.encode(oldFilename, StandardCharsets.UTF_8) +
                    "&username=" + URLEncoder.encode(username, StandardCharsets.UTF_8);
            nameResponse = getRequest(checkFileNameUrl);
        }
        System.out.print("Enter the new filename you want (spaces are allowed): ");
        String newFilename = scanner.nextLine().trim();
        while (newFilename.isEmpty()) {
            System.out.println("*******************************************************");
            System.out.println("File name cannot be empty.");
            System.out.print("Enter the new filename you want (spaces are allowed): ");
            newFilename = scanner.nextLine().trim();
        }
        String renameFileUrl = BASE_FILE_URL + "rename?oldFilename=" +
                URLEncoder.encode(oldFilename, StandardCharsets.UTF_8) +
                "&newFilename=" + URLEncoder.encode(newFilename, StandardCharsets.UTF_8) +
                "&username=" + URLEncoder.encode(username, StandardCharsets.UTF_8);
        HttpResponse<String> response = putRequest(renameFileUrl);
        System.out.println(response.body());
    }

    public void shareFile(Scanner scanner, String username) throws IOException, InterruptedException {
        System.out.println("*******************************************************");
        System.out.println("You can only share the file which you have uploaded.");
        System.out.print("Enter the filename you want to share (spaces are allowed): ");
        String filename = scanner.nextLine().trim();
        String checkFileNameUrl = BASE_FILE_URL + "checkFilenameForUser?filename=" +
                URLEncoder.encode(filename, StandardCharsets.UTF_8) +
                "&username=" + URLEncoder.encode(username, StandardCharsets.UTF_8);
        HttpResponse<String> nameResponse = getRequest(checkFileNameUrl);
        while (nameResponse.statusCode() == 200) {
            System.out.println("*******************************************************");
            System.out.println("The filename does not exist, please enter an existing file name to share.");
            System.out.print("Please enter the file name (spaces are allowed): ");
            filename = scanner.nextLine().trim();
            checkFileNameUrl = BASE_FILE_URL + "checkFilenameForUser?filename=" +
                    URLEncoder.encode(filename, StandardCharsets.UTF_8) +
                    "&username=" + URLEncoder.encode(username, StandardCharsets.UTF_8);
            nameResponse = getRequest(checkFileNameUrl);
        }
        System.out.println("Please enter the person username in the system to whom you want to share the file with.");
        System.out.print("Please enter the username: ");
        String desigantedUsername = scanner.nextLine().trim();
        while(desigantedUsername .isEmpty()) {
            System.out.println("Designated username cannot be empty. Try again.");
            System.out.print("Please enter the username: ");
            desigantedUsername = scanner.nextLine().trim();
        }
        String encodedUsername = URLEncoder.encode(desigantedUsername, StandardCharsets.UTF_8);
        String checkUsername = BASE_USER_URL + encodedUsername + "/check";
        HttpResponse<String> checkResponse = postRequest(checkUsername);
        int i = 0;
        while(checkResponse.statusCode() == 200){
            if(i == 3){
                System.out.println("Ran out of try again. Going back to main menu");
                return;
            }
            System.out.println("Designated username does not exist. Try again.");
            System.out.print("Please enter the correct username: ");
            desigantedUsername = scanner.nextLine().trim();
            checkUsername = BASE_USER_URL + URLEncoder.encode(desigantedUsername, StandardCharsets.UTF_8) + "/check";
            checkResponse = postRequest(checkUsername);
            i++;
        }
        String shareFilUrl = BASE_FILE_URL + "sharingFile?username="
                + URLEncoder.encode(username, StandardCharsets.UTF_8)
                + "&filename=" + URLEncoder.encode(filename, StandardCharsets.UTF_8)
                + "&designatedUserName=" + URLEncoder.encode(desigantedUsername, StandardCharsets.UTF_8);
        HttpResponse<String> response = postRequest(shareFilUrl);
        System.out.println(response.body());
    }

    // New postRequest method for byte[] payload
    private HttpResponse<String> postRequest(String url, byte[] data) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/octet-stream")
                .POST(HttpRequest.BodyPublishers.ofByteArray(data))
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> postRequest(String url) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> getRequest(String url) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET()
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> deleteRequest(String url) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .DELETE()
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> putRequest(String url) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .PUT(HttpRequest.BodyPublishers.noBody())
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    // Helper method to read exact number of bytes
    private byte[] readBytes(ByteArrayInputStream input, int length) throws IOException {
        byte[] bytes = new byte[length];
        int bytesRead = input.read(bytes);
        if (bytesRead != length) {
            throw new IOException("Expected " + length + " bytes, but read " + bytesRead);
        }
        return bytes;
    }

    // Helper method to convert 4 bytes to int
    private int bytesToInt(byte[] bytes) {
        return (bytes[0] & 0xFF) << 24 |
                (bytes[1] & 0xFF) << 16 |
                (bytes[2] & 0xFF) << 8  |
                (bytes[3] & 0xFF);
    }

    private byte[] intToBytes(int value) {
        return new byte[]{
                (byte) (value >>> 24),
                (byte) (value >>> 16),
                (byte) (value >>> 8),
                (byte) value
        };
    }

    private byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private byte[] decrypt(byte[] encryptedData, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(encryptedData);
    }

    private SecretKey generateKeyFromPassword(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_KEY_ALGORITHM);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, KEY_LENGTH);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }

    private byte[] encrypt(byte[] data, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

}
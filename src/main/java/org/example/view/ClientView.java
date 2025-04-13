package org.example.view;

import org.example.service.FileService;

import java.io.Console;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class ClientView {

    private static final String BASE_USER_URL = "http://localhost:8080/api/user/";
    private static final String BASE_FILE_URL = "http://localhost:8080/api/file/";
    private static final HttpClient client = HttpClient.newHttpClient();
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int SALT_LENGTH = 64;
    private static final int KEY_LENGTH = 64;
    private static final int ITERATION_COUNT = 10000;


    public void start() throws Exception {
        Scanner scanner = new Scanner(System.in);
        headerMenu();
        while (true) {
            displayMenu();
            String choice = scanner.nextLine();

            switch (choice) {
                case "1": // Register
                    handleRegister(scanner);
                    break;
                case "2": // Login
                    handleLogin(scanner);
                    break;
                case "3": // Forget Password
                    handleForgetPassword (scanner);
                    break;
                case "4": // Exit
                    handleExit(scanner);
                    return;
                default:
                    System.out.println("Invalid choice, try again.");
            }
        }
    }

    private void headerMenu() {
        System.out.println("*******************************************************");
        System.out.println("*          SECURE STORAGE SYSTEM                      *");
        System.out.println("*******************************************************");
    }

    private void displayMenu() {
        System.out.println("1. Register");
        System.out.println("2. Login");
        System.out.println("3. Forget Password");
        System.out.println("4. Exit");
        System.out.print("Enter your choice: ");
    }

    private void loginMenu(String username) {
        System.out.println("*******************************************************");
        System.out.println("Logged In Menu: Hi! " + username);
        System.out.println("1. Upload File ");
        System.out.println("2. Download File");
        System.out.println("3. Display Accessible Files");
        System.out.println("4. Rename File");
        System.out.println("5. Delete File");
        System.out.println("6. Share File");
        System.out.println("7. Change Password");
        System.out.println("8. Logout");
        System.out.print("Enter your choice: ");
    }

    private void adminMenu(String username){
        System.out.println("*******************************************************");
        System.out.println("Logged In Menu: Hi! " + username);
        System.out.println("1. View User logs");
        System.out.println("2. Change Password");
        System.out.println("3. Logout");
        System.out.print("Enter your choice: ");
    }


    // Generalized POST request method without body
    private static HttpResponse<String> postRequest(String url) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    // POST request with JSON body
    private static HttpResponse<String> postRequestWithBody(String url, String json) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    // Generalized PUT request method
    private static HttpResponse<String> putRequest(String url) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .PUT(HttpRequest.BodyPublishers.noBody())
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    // Generalized GET request method
    private static HttpResponse<String> getRequest(String url) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET()
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private static byte[] HmacSHA256(byte[] data, byte[] key) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance(HMAC_ALGORITHM);
            javax.crypto.spec.SecretKeySpec secretKey = new javax.crypto.spec.SecretKeySpec(key, HMAC_ALGORITHM);
            mac.init(secretKey);
            return mac.doFinal(data);
        } catch (java.security.NoSuchAlgorithmException | java.security.InvalidKeyException e) {
            throw new RuntimeException("HMAC256 Computation failed", e);
        }
    }

    private static String hashPassword(String password, byte[] salt) {
        byte[] hmacKey = generateRandomBytes(KEY_LENGTH);
        String saltBase64 = Base64.getEncoder().encodeToString(salt);
        byte[] hash = HmacSHA256((password + saltBase64).getBytes(), hmacKey);
        for (int i = 0; i < ITERATION_COUNT; i++) {
            hash = HmacSHA256(hash, hmacKey);
        }

        return Base64.getEncoder().encodeToString(hmacKey) + ":" + saltBase64 + ":" + Base64.getEncoder().encodeToString(hash);
    }

    private boolean verifyPassword(String password, String storedHash) {
        String[] parts = storedHash.split(":");
        if (parts.length != 3) return false;
        String hmacKeyEncoded = parts[0].trim();
        String saltEncoded = parts[1].trim();
        String hashEncoded = parts[2].trim();

        byte[] hmacKey = Base64.getDecoder().decode(hmacKeyEncoded);
        byte[] salt = Base64.getDecoder().decode(saltEncoded);
        byte[] originalHash = Base64.getDecoder().decode(hashEncoded);
        // Recompute the hash
        String saltBase64 = Base64.getEncoder().encodeToString(salt);
        byte[] computedHash = HmacSHA256((password + saltBase64).getBytes(), hmacKey);

        for (int i = 0; i < ITERATION_COUNT; i++) {
            computedHash = HmacSHA256(computedHash, hmacKey);
        }
        return slowEquals(originalHash, computedHash);
    }
    // Time comparison to prevent timing attacks
    private boolean slowEquals(byte[] a, byte[] b) {
        int diff = a.length ^ b.length;
        for (int i = 0; i < a.length && i < b.length; i++) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }

    private static String hashToken(String inputToken, byte[] salt) {
        byte[] hmacKey = generateRandomBytes(KEY_LENGTH);
        String saltBase64 = Base64.getEncoder().encodeToString(salt);
        byte[] hash = HmacSHA256((inputToken + saltBase64).getBytes(), hmacKey);
        for (int i = 0; i < ITERATION_COUNT; i++) {
            hash = HmacSHA256(hash, hmacKey);
        }

        return Base64.getEncoder().encodeToString(hmacKey) + ":" + saltBase64 + ":" + Base64.getEncoder().encodeToString(hash);
    }
    private boolean verifyToken(String token, String storedHash) {
        String[] parts = storedHash.split(":");
        if (parts.length != 3) return false;
        String hmacKeyEncoded = parts[0].trim();
        String saltEncoded = parts[1].trim();
        String hashEncoded = parts[2].trim();

        byte[] hmacKey = Base64.getDecoder().decode(hmacKeyEncoded);
        byte[] salt = Base64.getDecoder().decode(saltEncoded);
        byte[] originalHash = Base64.getDecoder().decode(hashEncoded);
        // Recompute the hash
        String saltBase64 = Base64.getEncoder().encodeToString(salt);
        byte[] computedHash = HmacSHA256((token + saltBase64).getBytes(), hmacKey);

        for (int i = 0; i < ITERATION_COUNT; i++) {
            computedHash = HmacSHA256(computedHash, hmacKey);
        }
        return slowEquals(originalHash, computedHash);
    }

    // Handle user registration with request body
    public static void handleRegister(Scanner scanner) throws IOException, InterruptedException {
        System.out.println("*******************************************************");
        System.out.println("Please enter the credentials for registering: ");
        String username;
        int noOfTrials = 0;
        while(true){
            if(noOfTrials == 3){
                System.out.println("Ran out of try again. Going back to main menu");
                return;
            }
            System.out.print("Please enter the username: ");
            username = scanner.nextLine().trim();
            if (username.isEmpty()) {
                System.out.println("Username cannot be empty. Try again.");
                noOfTrials++;
                continue;
            }
            if(username.length() < 3){
                System.out.println("Username cannot be less than 3 characters.");
                noOfTrials++;
                continue;
            }
            String checkUsername = BASE_USER_URL + URLEncoder.encode(username, StandardCharsets.UTF_8) + "/check";
            HttpResponse<String> checkResponse = postRequest(checkUsername);
            if(checkResponse.statusCode() == 200) break;
            System.out.println(checkResponse.body());
            noOfTrials++;
        }
        String password;
        int passwordTry = 0;
        while(true){
            if(passwordTry == 3){
                System.out.println("Ran out of try again. Going back to main menu");
                return;
            }
            System.out.print("Please enter the password: ");
            password = scanner.nextLine().trim();
            if (password.isEmpty()) {
                System.out.println("Password cannot be empty. Try again.");
                passwordTry++;
                continue;
            }
            if(password.length() >= 8) break;
            System.out.println("Password cannot be less than 8 characters.");
            passwordTry++;
        }
        String email;
        int emailTry = 0;
        while(true){
            if(emailTry == 3){
                System.out.println("Ran out of try again. Going back to main menu");
                return;
            }
            System.out.print("Please enter the email: ");
            email = scanner.nextLine().trim();
            if(email.isEmpty()){
                System.out.println("Email cannot be empty. Try again.");
                emailTry++;
                continue;
            }
            if (email.matches("^[A-Za-z0-9+_.-]+@(.+)$")) break;
            System.out.println("Invalid, please use a valid format (e.g., user@example.com).");
            emailTry++;
        }
        byte[] salt = generateRandomBytes(SALT_LENGTH);
        String hashedPassword = hashPassword(password, salt);
        String json = String.format("{\"username\":\"%s\",\"password\":\"%s\",\"email\":\"%s\"}",
                username, hashedPassword, email);
        String registerUserUrl = BASE_USER_URL + "register";
        HttpResponse<String> response = postRequestWithBody(registerUserUrl, json);
        if (response.statusCode() == 200) {
            System.out.println("Registration successful! please login now.");
        } else {
            System.out.println("Registration failed: " + response.body());
        }
    }

    // Handle login with query parameters
//    private void handleLogin(Scanner scanner) throws Exception {
//        System.out.println("*******************************************************");
//        System.out.println("Please enter the credentials for logging in:");
//        String username;
//        int loginTry = 0;
//        while (true) {
//            if (loginTry == 3) {
//                System.out.println("Ran out of try again. Going back to main menu");
//                return;
//            }
//            System.out.print("Please enter your username: ");
//            username = scanner.nextLine().trim();
//            if (username.isEmpty()) {
//                System.out.println("Username cannot be empty. Try again.");
//                loginTry++;
//                continue;
//            }
//            if (username.length() < 3) {
//                System.out.println("Username cannot be less than 3 characters.");
//                loginTry++;
//                continue;
//            }
//            String checkUsername = BASE_USER_URL + URLEncoder.encode(username, StandardCharsets.UTF_8) + "/check";
//            HttpResponse<String> checkResponse = postRequest(checkUsername);
//            if (checkResponse.statusCode() == 400) break; // Assuming 400 means username exists
//            System.out.println("Invalid username, please enter the correct username.");
//            loginTry++;
//        }
//
//        String password;
//        int passwordTry = 0;
//        while (true) {
//            if (passwordTry == 3) {
//                System.out.println("Ran out of try again. Going back to main menu");
//                return;
//            }
//            System.out.print("Please enter your password: ");
//            password = scanner.nextLine().trim();
//            if (password.isEmpty()) {
//                System.out.println("Password cannot be empty. Try again.");
//                passwordTry++;
//                continue;
//            }
//            if (password.length() >= 8) break;
//            System.out.println("Password cannot be less than 8 characters.");
//            passwordTry++;
//        }
//
//        // Fetch the stored hashed password from the server
//        String getHashedPasswordUrl = BASE_USER_URL + "getHashedPassword?username=" + URLEncoder.encode(username, StandardCharsets.UTF_8);
//        HttpResponse<String> response = getRequest(getHashedPasswordUrl);
//        String hashedPasswordFromServer = response.body();
//
//        if (response.statusCode() != 200) {
//            System.out.println("Login failed: Unable to retrieve credentials from server.");
//            return;
//        }
//
//        // Verify the password
//        if (verifyPassword(password, hashedPasswordFromServer)) {
//            // Generate a timestamp
//            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
//
//            // Generate a signature using username, timestamp, and hashed password as the key
//            String dataToSign = timestamp + "|" + username;
//            byte[] hmacKey = Base64.getDecoder().decode(hashedPasswordFromServer.split(":")[0]); // Use the HMAC key from stored hash
//            String signature = generateSignature(dataToSign, hmacKey);
//
//            // Send login request with signature to the server
//            String setLogInUrl = BASE_USER_URL + "login?username=" + URLEncoder.encode(username, StandardCharsets.UTF_8) +
//                    "&password=" + URLEncoder.encode(hashedPasswordFromServer.trim(), StandardCharsets.UTF_8) +
//                    "&signature=" + URLEncoder.encode(signature, StandardCharsets.UTF_8);
//            HttpResponse<String> login = postRequest(setLogInUrl);
//            System.out.println(login.body());
//
//            if (login.statusCode() == 200) {
//                if (username.equals("admin")) {
//                    handleAdminAuthorization(username, hashedPasswordFromServer);
//                } else {
//                    handleAuthorization(username, hashedPasswordFromServer, signature);
//                }
//            } else {
//                System.out.println("Login failed: " + login.body());
//            }
//        } else {
//            System.out.println("Login failed: Invalid username or password.");
//        }
//    }

    // Helper method to generate signature
    private String generateSignature(String data, byte[] key) {
        byte[] signatureBytes = HmacSHA256(data.getBytes(StandardCharsets.UTF_8), key);
        return bytesToHex(signatureBytes);
    }

    // Convert byte array to hex string
    private String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    private void handleLogin(Scanner scanner) throws Exception {
        System.out.println("*******************************************************");
        System.out.println("Please enter the credentials for logging in:");
        String username;
        Console console = System.console();
        int loginTry = 0;
        while(true){
            if(loginTry == 3){
                System.out.println("Ran out of try again. Going back to main menu");
                return;
            }
            System.out.print("Please enter your username: ");
            if (console != null) {
                username = new String(console.readLine());
            } else {
                username = scanner.nextLine().trim();
            }

            if(username.isEmpty()){
                System.out.println("Username cannot be empty. Try again.");
                loginTry++;
                continue;  // Changed from break to continue
            }
            if(username.length() < 3){
                System.out.println("Username cannot be less than 3 characters.");
                loginTry++;
                continue;
            }
            String checkUsername = BASE_USER_URL + URLEncoder.encode(username, StandardCharsets.UTF_8) + "/check";
            HttpResponse<String> checkResponse = postRequest(checkUsername);
            if(checkResponse.statusCode() == 400) break;
            System.out.println("Invalid username, please enter the correct username.");
            loginTry++;
        }
        String password;
        int passwordTry = 0;
        while(true){
            if(passwordTry == 3){
                System.out.println("Ran out of try again. Going back to main menu");
                return;
            }
            System.out.print("Please enter your password: ");
            if(console != null) {
                char[] passwordArray = console.readPassword();
                password = new String(passwordArray);
                if(password.length() <= 8) break;
                System.out.println("Password cannot be less than 8 characters.");
                passwordTry++;
            }
            else{
            password = scanner.nextLine().trim();}
            if(password.isEmpty()){
                System.out.println("Password cannot be empty. Try again.");
                passwordTry++;
                continue;
            }
            if(password.length() >= 8) break;
            System.out.println("Password cannot be less than 8 characters.");
            passwordTry++;
        }
        String getHashedPasswordUrl = BASE_USER_URL + "getHashedPassword?username=" + URLEncoder.encode(username, StandardCharsets.UTF_8);
        HttpResponse<String> response = getRequest(getHashedPasswordUrl);
        //System.out.println(response.statusCode());
        String hashedPasswordFromServer = response.body();
        // Generate a timestamp
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        // Generate a signature using username, timestamp, and hashed password as the key
        String dataToSign = timestamp + "|" + username;
        byte[] hmacKey = Base64.getDecoder().decode(hashedPasswordFromServer.split(":")[0]); // Use the HMAC key from stored hash
        String signature = generateSignature(dataToSign, hmacKey);
        // Send login request with signature to the server
        // This is not fully right, need to implement verify also
        if(username.equals("admin") && verifyPassword(password, response.body())){
            //if(verifyPassword(password, response.body())){
                String setAdminLogInUrl = BASE_USER_URL + "login?username=" + URLEncoder.encode(username, StandardCharsets.UTF_8) + "&password=" + URLEncoder.encode(response.body().trim(), StandardCharsets.UTF_8) + "&signature=" + URLEncoder.encode(signature, StandardCharsets.UTF_8);
                HttpResponse<String> adminLogin = postRequest(setAdminLogInUrl);
                System.out.println(adminLogin.body());
                handleAdminAuthorization(username, response.body(), signature);
            //}
        }else if(verifyPassword(password, response.body())){
            // Send login request with signature to the server
            String setLogInUrl = BASE_USER_URL + "login?username=" + URLEncoder.encode(username, StandardCharsets.UTF_8) +
                    "&password=" + URLEncoder.encode(hashedPasswordFromServer.trim(), StandardCharsets.UTF_8) +
                    "&signature=" + URLEncoder.encode(signature, StandardCharsets.UTF_8);
            HttpResponse<String> login = postRequest(setLogInUrl);
            //String setLogInUrl = BASE_USER_URL + "login?username=" + URLEncoder.encode(username, StandardCharsets.UTF_8) + "&password=" + URLEncoder.encode(response.body().trim(), StandardCharsets.UTF_8);
            //HttpResponse<String> login = postRequest(setLogInUrl);
            System.out.println(login.body());
            //here need to pass hashed password for authorization for encryption
            handleAuthorization(username, response.body(), signature);
        }else {
            System.out.println("Login failed: Invalid username or password.");
            return;
        }
    }
    public static void handleForgetPassword(Scanner scanner) throws IOException, InterruptedException {
        System.out.println("*******************************************************\n");
        System.out.println("Please enter credentials of account to be recovered: ");
        String username;
        System.out.print("Enter username of account: ");
        username = scanner.nextLine().trim();
        int noOfTrials = 0;
//        // obtain username from the user (and check if the username exists)
//        while(true){
//            if(noOfTrials == 3){
//                System.out.println("Ran out of try again. Going back to main menu");
//                return;
//            }
//            System.out.print("Please enter the username: ");
//            username = scanner.nextLine().trim();
//            if (username.isEmpty()) {
//                System.out.println("Username cannot be empty. Try again.");
//                noOfTrials++;
//                continue;
//            }
//            if(username.length() < 3){
//                System.out.println("Username cannot be less than 3 characters.");
//                noOfTrials++;
//                continue;
//            }
//            String checkUsername = BASE_USER_URL + URLEncoder.encode(username, StandardCharsets.UTF_8) + "/check"; // checking if the username is registered
//            HttpResponse<String> checkResponse = postRequest(checkUsername);
//            if(checkResponse.statusCode() == 200) break;
//            System.out.println(checkResponse.body());
//            noOfTrials++;
//        }
        // use username to trigger the getToken() method in the server: /initiate-forgot-password
        String generateMFAToken = BASE_USER_URL + "initiate-forget-password?username=" + URLEncoder.encode(username, StandardCharsets.UTF_8);
        HttpResponse<String> response = postRequest(generateMFAToken);
        System.out.println(response.statusCode());
        System.out.println (response.body()); // now, email should have been sent to user

        // obtain the pin from the user to initiate the submitToken() method in the server: /submit-token-password
        String inputToken;
        int noOfTokenTrials = 0;
        while (true){
            if (noOfTokenTrials==3){System.out.println ("You have exceeded the maximum no of input attempts. Please try again later.");
                return;
            }
            System.out.print("Please enter MFA OTP sent to email inbox: ");
            inputToken = scanner.nextLine().trim();
            System.out.print(inputToken);
            if (inputToken.isEmpty()) {
                System.out.println("Inputted Token cannot be empty. Try again.");
                noOfTokenTrials++;
                continue;
            }
            if(inputToken.length() < 6){
                System.out.println("Inputted Token cannot be less than 6 characters.");
                noOfTokenTrials++;
                continue;
            }
            byte[] salt = generateRandomBytes(SALT_LENGTH);
            String hashedToken = hashToken(inputToken,salt);
            //noOfTokenTrials++; // for now this is a placeholder. Need to loop 3 times (place in the end of this else block)
            String json = String.format("{\"username\":\"%s\",\"pin\":\"%s\"}", username, inputToken);
            String submitTokenUrl = BASE_USER_URL + "submit-token-password";
            HttpResponse<String> response2 = postRequestWithBody(submitTokenUrl, json);
            if (response2.statusCode() == 200) {
                System.out.println("Multi-Factor Authentication was successful!\n");
                break;
            } else {
                System.out.println("Multi-Factor Authentication failed: " + response2.body());
                System.out.println("Input token was ." + inputToken +"\n hashed token was :" + hashedToken);
            }
            noOfTokenTrials++;
            // place noOfTokenTrials++; here
        }
        // obtain the new password from the user (and confirm password), then call the changePassword() method: /changePassword
        System.out.println("Please update your password below\n");
        String newPassword, confirmPassword;
        int passwordTry = 0;
        while(true){
            if(passwordTry == 2){
                System.out.println("Ran out of try again. Going back to main menu");
                return;
            }
            System.out.print("Enter new password: ");
            newPassword = scanner.nextLine();
            System.out.print("Confirm new password: ");
            confirmPassword = scanner.nextLine();
            if(newPassword.equals(confirmPassword)) break;
            System.out.println("New password and confirm new password are not matching, Enter them again.");
            passwordTry++;
        }
        byte[] salt = generateRandomBytes(SALT_LENGTH);
        String hashedPassword = hashPassword(newPassword, salt);
        String changePasswordUrl = BASE_USER_URL + "changePassword?username=" + URLEncoder.encode(username, StandardCharsets.UTF_8) + "&newPassword=" + URLEncoder.encode(hashedPassword, StandardCharsets.UTF_8);
        HttpResponse<String> response3 = putRequest(changePasswordUrl);
        System.out.println(response3.body());

    }

    private void handleExit(Scanner scanner) {
        System.out.println("*******************************************************");
        System.out.println("Exiting system. Goodbye!");
        scanner.close();
    }

    private void handleAdminAuthorization(String username, String password, String signature) throws Exception {
        Scanner scanner = new Scanner(System.in);
        while (true) {
            adminMenu(username);
            String choice = scanner.nextLine();
            switch (choice) {
                case "1":
                    handleAdminView(username, password);
                    break;
                case "2":
                    handleChangePassword(scanner, username, password);
                    break;
                case "3":
                    handleUserLogout(username, signature);
                    return;
                default:
                    System.out.println("Invalid choice, try again");
            }
        }
    }

    private void handleAuthorization(String username, String password, String signature) throws Exception {
        Scanner scanner = new Scanner(System.in);
        while (true) {
            loginMenu(username);
            String choice = scanner.nextLine();
            switch (choice) {
                case "1":
                    handleUpload(scanner, username, password, signature);
                    break;
                case "2":
                    handleDownload(scanner, username, password);
                    break;
                case "3":
                    handleDisplayFiles(username, "");
                    handleDisplaySharedFiles(username);
                    break;
                case "4":
                    handleRenameFiles(scanner, username);
                    break;
                case "5":
                    handleDeleteFiles(scanner, username, signature);
                    break;
                case "6":
                    handleShareFile(scanner, username, signature);
                    break;
                case "7":
                    handleChangePassword(scanner, username, password);
                    break;
                case "8":
                    handleUserLogout(username, signature);
                    return;
                default:
                    System.out.println("Invalid choice, try again");
            }
        }
    }

//    private void handleAdminView(String username, String password) throws IOException, InterruptedException {
//        System.out.println("*********************************************************************************************************************************************************************");
//        System.out.println("Below is the list of user logs.");
//        System.out.println("*********************************************************************************************************************************************************************");
//        String adminView = BASE_USER_URL + "getLogsForAdmin?adminName=" + username + "&adminPassword=" + password;
//        HttpResponse<String> response = getRequest(adminView);
//        System.out.println(response.body());
//    }

    private void handleAdminView(String username, String password) throws IOException, InterruptedException {
        System.out.println("*********************************************************************************************************************************************************************");
        System.out.println("Below is the list of user logs.");
        System.out.println("*********************************************************************************************************************************************************************");

        // Construct the URL with correct parameter names
        String adminView = BASE_USER_URL + "getLogsForAdmin?adminName=" + username + "&adminPassword=" + password;

        // Send the HTTP GET request
        HttpResponse<String> response = getRequest(adminView);

        // Check if the response is successful (status code 200)
        if (response.statusCode() == 200) {
            // Parse the response using your custom method
            List<String> logs = parseJsonResponse(response.body());

            // Check if the list is empty
            if (logs.isEmpty()) {
                System.out.println("No logs available.");
            } else {
                // Print each log entry on a new line, removing spaces around colons
                for (String log : logs) {
                    String formattedLog = log.replace(": ", ":"); // Remove space after colons
                    System.out.println(formattedLog);
                }
            }
        } else {
            // Handle error responses
            System.out.println("Failed to retrieve logs. Status: " + response.statusCode());
            System.out.println("Response: " + response.body());
        }
    }

    private void handleUpload(Scanner scanner, String username, String password, String signature) throws Exception  {
        FileService fileService = new FileService();
        fileService.uploadFile(scanner, username, password, signature);
    }

    private void handleDownload(Scanner scanner, String username, String password) throws Exception{
        System.out.println("*******************************************************");
        System.out.println("Would you like to download or read the files you have uploaded, or the files shared with you by other users?");
        int option = 0, numberOfTry = 0;
        while(true){
            if(numberOfTry == 3){
                System.out.println("Ran out of try again. Going back to main menu");
                return;
            }
            System.out.print("Please choose 1 to download the files you have uploaded, or 2 to download the files shared with you: ");
            option = scanner.nextInt();
            if(option == 1 || option == 2) break;
            System.out.println("Enter a valid number to make your selection: either 1 or 2.");
            numberOfTry++;
        }
        FileService fileService = new FileService();
        if(option == 1){
            boolean breakPoint = handleDisplayFiles(username, "download");
            if(breakPoint) return;
            fileService.downloadFile(scanner, username, password, "downloadUploadedFile");
        }else{
            boolean breakPoint = handleDisplaySharedFiles(username);;
            if(breakPoint) {
                System.out.println("Since, no files has been shared with you, you can download none.");
                //handleAuthorization(username, password);
                return;
            }
            fileService.downloadFile(scanner, username, password, "downloadSharedFile");
        }
    }

    private boolean handleDisplayFiles(String username, String situation) throws IOException, InterruptedException {
        String getFilesUrl = BASE_FILE_URL + "displayFiles?username=" + username;
        System.out.println("*******************************************************");
        HttpResponse<String> response = getRequest(getFilesUrl);
        String jsonResponse = response.body();
        if (response.statusCode() == 200) {
            // Parse JSON array manually
            List<String> fileNames = parseFileNames(jsonResponse);
            if (fileNames.isEmpty()) {
                System.out.println("No files found for user: " + username);
                if(situation.equals("rename")){
                    System.out.println("Since, you have no files uploaded, you can rename none.");
                    return  true;
                }
                if(situation.equals("delete")){
                    System.out.println("Since, you have no files uploaded, you can delete none.");
                    return  true;
                }
                if(situation.equals("share")){
                    System.out.println("Since, you have no files uploaded, you can share none.");
                    return  true;
                }
                if(situation.equals("download")){
                    System.out.println("Since, you have no files uploaded, you can download none.");
                    return  true;
                }
            } else {
                System.out.println("Files uploaded by user: " + username);
                int i = 1;
                for (String fileName : fileNames) {
                    System.out.println(i++ + ". " + fileName);
                }
            }
        } else {
            System.out.println("Error fetching files: " + response.statusCode() + " - " + jsonResponse);
        }
        return false;
    }

    private boolean handleDisplaySharedFiles(String username) throws IOException, InterruptedException {
        String getSharedFilesUrl = BASE_FILE_URL + "displaySharedFiles?username=" + URLEncoder.encode(username, StandardCharsets.UTF_8);
        System.out.println("*******************************************************");
        HttpResponse<String> response = getRequest(getSharedFilesUrl);
        String jsonResponse = response.body();
        // Parse JSON response
        List<String> parsedResponse = parseJsonResponse(jsonResponse);
        if (response.statusCode() == 200) {
            // Files exist, display them one by one
            System.out.println("Shared files for user: " + username);
            System.out.println("Here shared file is viewed as file name: file owner name");
            int i = 1;
            for (String fileName : parsedResponse) {
                System.out.println(i++ + ". " + fileName);
            }
        } else if (response.statusCode() == 400) {
            // No files or error, display the message
            System.out.println(parsedResponse.get(0)); // Single message from bad request
            return true;
        } else {
            System.out.println("Unexpected response: " + response.statusCode() + " - " + jsonResponse);
        }
        return false;
    }

    private List<String> parseJsonResponse(String json) {
        List<String> items = new ArrayList<>();
        if (json == null || json.equals("[]")) {
            return items; // Empty list for null or empty array
        }
        // Remove [ and ]
        String trimmedJson = json.substring(1, json.length() - 1);
        if (trimmedJson.isEmpty()) {
            return items;
        }
        // Split by "," (comma followed by a quote) to separate array elements
        String[] elements = trimmedJson.split("\",\\s*\"");
        for (int i = 0; i < elements.length; i++) {
            // Remove leftover quotes from the first and last elements
            String cleanElement = elements[i];
            if (i == 0) {
                cleanElement = cleanElement.replaceFirst("^\"", ""); // Remove leading quote from first element
            }
            if (i == elements.length - 1) {
                cleanElement = cleanElement.replaceFirst("\"$", ""); // Remove trailing quote from last element
            }
            items.add(cleanElement.trim());
        }
        return items;
    }

//    // Manually parse JSON array of strings
//    private List<String> parseJsonResponse(String json) {
//        List<String> items = new ArrayList<>();
//        if (json == null || json.equals("[]")) {
//            return items; // Empty list for null or empty array
//        }
//        // Remove [ and ] and split by comma
//        String trimmedJson = json.substring(1, json.length() - 1); // e.g., "file1.txt","file2.txt" or "message"
//        String[] elements = trimmedJson.split(",\\s*");
//        for (String element : elements) {
//            // Remove quotes around each item
//            String cleanElement = element.replace("\"", "").trim();
//            items.add(cleanElement);
//        }
//        return items;
//    }

    private void handleRenameFiles(Scanner scanner, String username) throws IOException, InterruptedException {
        boolean breakPoint = handleDisplayFiles(username, "rename");
        if(breakPoint) return;
        FileService fileService = new FileService();
        fileService.renameFile(scanner, username);
    }

    private void handleDeleteFiles(Scanner scanner, String username, String signature) throws IOException, InterruptedException {
        boolean breakPoint = handleDisplayFiles(username, "delete");
        if(breakPoint) return;
        FileService fileService = new FileService();
        fileService.deleteFile(scanner, username, signature);
    }

    private void handleShareFile(Scanner scanner, String username, String signature) throws IOException, InterruptedException {
        boolean breakPoint = handleDisplayFiles(username, "share");
        if(breakPoint) return;
        FileService fileService = new FileService();
        fileService.shareFile(scanner, username, signature);
    }


    private void handleChangePassword(Scanner scanner, String username, String password) throws IOException, InterruptedException {
        System.out.println("*******************************************************");
        System.out.print("Enter your current password: ");
        Console console = System.console();
        String officialPassword;
        if (console != null) {
            char[] currentPasswordArray = console.readPassword();
            officialPassword = new String(currentPasswordArray);
        } else {
            System.out.println("Console not available. Please enter your password:");
            officialPassword = scanner.nextLine();
        }
        if(!verifyPassword(officialPassword, password)) {
            System.out.println("Invalid password, going back to main menu.");
            return;
        }
        String newPassword, confirmPassword;
        int passwordTry = 0;
        while(true){
            if(passwordTry == 2){
                System.out.println("Ran out of try again. Going back to main menu");
                return;
            }if(console != null) {
                System.out.print("Enter new password: ");
                char[] newPasswordArray = console.readPassword();
                newPassword = new String(newPasswordArray);
                System.out.print("Confirm new password: ");

                char[] confirmPasswordArray = console.readPassword();
                confirmPassword = new String(confirmPasswordArray);
                if(newPassword.equals(confirmPassword)) break;
                passwordTry++;
            } else {
                System.out.print("Enter new password: ");
                newPassword = scanner.nextLine();
                System.out.print("Confirm new password: ");
                confirmPassword = scanner.nextLine();
                if(newPassword.equals(confirmPassword)) break;
                System.out.println("New password and confirm new password are not matching, Enter them again.");
                passwordTry++;
            }
            System.out.println("New password and confirm new password are not matching, Enter them again.");
            passwordTry++;
        }
        byte[] salt = generateRandomBytes(SALT_LENGTH);
        String hashedPassword = hashPassword(newPassword, salt);
        String changePasswordUrl = BASE_USER_URL + "changePassword?username=" + URLEncoder.encode(username, StandardCharsets.UTF_8) + "&newPassword=" + URLEncoder.encode(hashedPassword, StandardCharsets.UTF_8);
        HttpResponse<String> response = putRequest(changePasswordUrl);
        System.out.println(response.body());
    }

    private void handleUserLogout(String username, String signature) throws IOException, InterruptedException {
        String logoutUrl = BASE_USER_URL + "logout?username="
                +  URLEncoder.encode(username, StandardCharsets.UTF_8)
                + "&signature=" + URLEncoder.encode(signature, StandardCharsets.UTF_8);
        HttpResponse<String> response = postRequest(logoutUrl);
        System.out.println(response.body());
        System.out.println("*******************************************************");
    }

    // Manually parse JSON array of strings
    private List<String> parseFileNames(String json) {
        List<String> fileNames = new ArrayList<>();
        if (json.equals("[]")) {
            return fileNames; // Empty list
        }
        // Remove [ and ] and split by comma
        String trimmedJson = json.substring(1, json.length() - 1); // e.g., "file1.txt","file2.txt"
        String[] names = trimmedJson.split(",\\s*");
        for (String name : names) {
            // Remove quotes around each filename
            String cleanName = name.replace("\"", "").trim();
            fileNames.add(cleanName);
        }
        return fileNames;
    }

}

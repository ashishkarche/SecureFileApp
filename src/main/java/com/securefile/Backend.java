package com.securefile;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.MessageDigest;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Properties;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.mail.Authenticator;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

public class Backend {
    // Database Connection Constants
    private static final String DB_URL = "jdbc:mysql://localhost:3306/filedatabase";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = ""; // Replace with your database password

    // Table Names
    private static final String USER_TABLE = "users";
    private static final String ENCRYPTED_FILES_TABLE = "encrypted_files";
    private static final String KEY_TABLE = "keys";

    // Encryption Keys
    private static SecretKey aesSecretKey;
    private static SecretKey desSecretKey;

    // User session
    private static UserSession userSession = UserSession.getInstance();

    // Initialize encryption keys
    public static void initializeEncryptionKeys() {
        try {
            aesSecretKey = retrieveOrCreateKey("aes_key", "AES");
            desSecretKey = retrieveOrCreateKey("des_key", "DES");
        } catch (GeneralSecurityException | SQLException e) {
            handleException(e);
        }
    }

    // Generate or retrieve a secret key
    private static SecretKey retrieveOrCreateKey(String keyName, String algorithm)
            throws GeneralSecurityException, SQLException {
        SecretKey key = retrieveKey(keyName);
        if (key == null) {
            key = generateKey(algorithm);
            storeKey(keyName, key);
        }
        return key;
    }

    // Error handling for exceptions
    private static void handleException(Exception e) {
        e.printStackTrace();
    }

    // Generate a new secret key
    private static SecretKey generateKey(String algorithm) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
        SecureRandom secureRandom = new SecureRandom();
        keyGen.init(secureRandom);
        return keyGen.generateKey();
    }

    // Store a secret key in the database
    private static void storeKey(String keyName, SecretKey key) throws SQLException {
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                PreparedStatement statement = connection
                        .prepareStatement("INSERT INTO `" + KEY_TABLE + "` (key_name, key_data) VALUES (?, ?)")) {
            statement.setString(1, keyName);
            statement.setBytes(2, serialize(key));
            statement.executeUpdate();
        }
    }

    // Retrieve a secret key from the database
    private static SecretKey retrieveKey(String keyName) throws SQLException {
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                PreparedStatement statement = connection
                        .prepareStatement("SELECT key_data FROM `" + KEY_TABLE + "` WHERE key_name = ?")) {
            statement.setString(1, keyName);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    return (SecretKey) deserialize(resultSet.getBytes("key_data"));
                }
            }
        }
        return null;
    }

    // Serialize an object into a byte array
    private static byte[] serialize(Object object) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
                ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(object);
            return bos.toByteArray();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // Deserialize a byte array into an object
    private static Object deserialize(byte[] bytes) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
                ObjectInputStream ois = new ObjectInputStream(bis)) {
            return ois.readObject();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * The function `encryptFileData` encrypts file data using AES and DES encryption algorithms and
     * returns the combined encrypted data.
     * 
     * @param fileData The `fileData` parameter is a byte array that represents the data of a file that
     * you want to encrypt. This data will be encrypted using two different encryption algorithms, AES
     * and DES, with their respective secret keys (`aesSecretKey` and `desSecretKey`). The method
     * `encrypt` is
     * @return The `encryptFileData` method returns a byte array containing the encrypted data using
     * both AES and DES encryption algorithms.
     */
    public static byte[] encryptFileData(byte[] fileData) throws GeneralSecurityException, IOException {
        byte[] encryptedDataAES = encrypt(fileData, aesSecretKey, "AES");
        byte[] encryptedDataDES = encrypt(fileData, desSecretKey, "DES");
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(encryptedDataAES);
        outputStream.write(encryptedDataDES);
        return outputStream.toByteArray();
    }

    /**
     * This Java function decrypts a byte array containing data encrypted with both AES and DES
     * algorithms and returns the decrypted data.
     * 
     * @param encryptedData The `decryptFileData` method you provided seems to be decrypting a file
     * that has been encrypted using both AES and DES algorithms. The method splits the encrypted data
     * into two halves, decrypts each half using the corresponding secret key and algorithm, and then
     * combines the decrypted data before returning it.
     * @return The `decryptFileData` method returns a byte array containing the decrypted data from
     * both the AES and DES encryption algorithms.
     */
    public static byte[] decryptFileData(byte[] encryptedData) throws GeneralSecurityException, IOException {
        int halfLength = encryptedData.length / 2;
        byte[] encryptedDataAES = Arrays.copyOfRange(encryptedData, 0, halfLength);
        byte[] encryptedDataDES = Arrays.copyOfRange(encryptedData, halfLength, encryptedData.length);
        byte[] decryptedDataAES = decrypt(encryptedDataAES, aesSecretKey, "AES");
        byte[] decryptedDataDES = decrypt(encryptedDataDES, desSecretKey, "DES");
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(decryptedDataAES);
        outputStream.write(decryptedDataDES);
        return outputStream.toByteArray();
    }

    /**
     * The function encrypts a byte array using a specified algorithm and secret key in Java.
     * 
     * @param data The `data` parameter is the byte array that you want to encrypt using the specified
     * algorithm and secret key.
     * @param key The `key` parameter in the `encrypt` method is of type `SecretKey` and is used as the
     * secret key for encryption. It is essential for encrypting the data using the specified
     * algorithm.
     * @param algorithm The `algorithm` parameter in the `encrypt` method refers to the specific
     * encryption algorithm that will be used for encrypting the data. Examples of encryption
     * algorithms include AES (Advanced Encryption Standard), DES (Data Encryption Standard), and RSA
     * (Rivest-Shamir-Adleman). The algorithm
     * @return The method `encrypt` returns a byte array that represents the encrypted data after
     * performing encryption using the specified algorithm and secret key.
     */
    private static byte[] encrypt(byte[] data, SecretKey key, String algorithm) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    /**
     * The `decrypt` function takes encrypted data, a secret key, and an encryption algorithm as input,
     * then decrypts the data using the specified algorithm and returns the decrypted byte array.
     * 
     * @param encryptedData The `encryptedData` parameter is a byte array that contains the data to be
     * decrypted. This data has been encrypted using a specific encryption algorithm and needs to be
     * decrypted using the provided secret key and algorithm.
     * @param key The `key` parameter in the `decrypt` method is a `SecretKey` object that is used for
     * decryption. This key should be the same key that was used for encryption in order to
     * successfully decrypt the data.
     * @param algorithm The `algorithm` parameter in the `decrypt` method refers to the specific
     * cryptographic algorithm that is used for decryption. Examples of cryptographic algorithms
     * include AES (Advanced Encryption Standard), DES (Data Encryption Standard), and RSA
     * (Rivest-Shamir-Adleman). When calling the `decrypt`
     * @return The method is returning the decrypted byte array after performing the decryption
     * operation using the provided key and algorithm.
     */
    private static byte[] decrypt(byte[] encryptedData, SecretKey key, String algorithm)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encryptedData);
    }

    // User login authentication code with IP address verification
    public static boolean authenticateUser(String username, String password, String ipAddress) {
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                PreparedStatement statement = connection.prepareStatement(
                        "SELECT id, username, email, password, ip_address FROM " + USER_TABLE
                                + " WHERE username = ?")) {
            statement.setString(1, username);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    int userId = resultSet.getInt("id");
                    String userEmail = resultSet.getString("email"); // Retrieve user's email
                    String hashedPassword = resultSet.getString("password");
                    String savedIpAddress = resultSet.getString("ip_address");
                    // Verify username, password, and IP address
                    if (verifyPassword(password, hashedPassword) && ipAddress.equals(savedIpAddress)) {
                        // Store user's email in the session
                        userSession.loginUser(userId, username, userEmail);
                        return true;
                    }
                }
            }
        } catch (SQLException | NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        }
        return false;
    }

    /**
     * The function `authenticateAdmin` checks if the provided username and password match an entry in
     * the admins table of a database and returns true if authentication is successful.
     * 
     * @param username The `username` parameter is the username of the admin trying to authenticate.
     * @param password The `password` parameter in the `authenticateAdmin` method is the password
     * provided by the user attempting to authenticate as an admin. This password is used in
     * conjunction with the `username` to query the database and check if there is a matching record in
     * the `admins` table with the provided username and
     * @return The method `authenticateAdmin` returns a boolean value indicating whether the
     * authentication of an admin with the given username and password was successful. If the query to
     * the database returns at least one row for the provided username and password in the admins
     * table, the method returns `true`, indicating successful authentication. If there is an SQL
     * exception during the process, the method catches the exception, prints the stack trace, and
     */
    public static boolean authenticateAdmin(String username, String password) {
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                PreparedStatement statement = connection.prepareStatement(
                        "SELECT id FROM admins WHERE username = ? AND password = ?")) {
            statement.setString(1, username);
            statement.setString(2, password);
            try (ResultSet resultSet = statement.executeQuery()) {
                return resultSet.next(); // If result set has at least one row, admin authentication is successful
            }
        } catch (SQLException ex) {
            ex.printStackTrace();
            return false;
        }
    }

    
    /**
     * The `registerUser` function in Java registers a new user by checking email and username
     * validity, hashing the password, and storing user information in a database table.
     * 
     * @param email Email address of the user registering for an account.
     * @param username The `username` parameter in the `registerUser` method is a String that
     * represents the username chosen by the user during the registration process. This username will
     * be stored in the database along with other user information such as email, password, and IP
     * address. It is used to uniquely identify the user within
     * @param password The `password` parameter in the `registerUser` method is a String that
     * represents the password chosen by the user during registration. This password is then hashed
     * using a hashing algorithm before being stored in the database for security reasons.
     * @param ipAddress The `ipAddress` parameter in the `registerUser` method is used to store the IP
     * address of the user who is registering. This information can be helpful for tracking user
     * activity, identifying potential security risks, and ensuring that each user account is
     * associated with a unique IP address. Storing the IP
     * @return The `registerUser` method returns a boolean value. It returns `true` if the user
     * registration is successful (i.e., the user is successfully added to the database), and it
     * returns `false` if the registration fails due to invalid email, existing email or username,
     * database connection issues, password hashing errors, or any SQL exceptions.
     */
    public static boolean registerUser(String email, String username, String password, String ipAddress) {
        if (!isValidEmail(email) || isEmailRegistered(email) || isUsernameTaken(username)) {
            return false;
        }
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                PreparedStatement statement = connection.prepareStatement(
                        "INSERT INTO " + USER_TABLE + " (email, username, password, ip_address) VALUES (?, ?, ?, ?)")) {
            statement.setString(1, email); // Add email to registration query
            statement.setString(2, username);
            statement.setString(3, hashPassword(password)); // Hashing the password
            statement.setString(4, ipAddress); // Store IP address
            int rowsAffected = statement.executeUpdate();
            return rowsAffected > 0; // If at least one row is affected, registration succeeds
        } catch (SQLException | NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            return false;
        }
    }

    // Method to validate email address format
    public static boolean isValidEmail(String email) {
        String emailRegex = "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$";
        Pattern pattern = Pattern.compile(emailRegex);
        Matcher matcher = pattern.matcher(email);
        return matcher.matches();
    }

    // Check if the email is already registered
    public static boolean isEmailRegistered(String email) {
        return isFieldExists("email", email, USER_TABLE);
    }

    // Check if the username is already taken
    public static boolean isUsernameTaken(String username) {
        return isFieldExists("username", username, USER_TABLE);
    }

    // Check if a field value exists in a table
    private static boolean isFieldExists(String fieldName, String value, String tableName) {
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                PreparedStatement statement = connection
                        .prepareStatement("SELECT COUNT(*) AS count FROM " + tableName + " WHERE " + fieldName + " = ?")) {
            statement.setString(1, value);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    int count = resultSet.getInt("count");
                    return count > 0;
                }
            }
        } catch (SQLException ex) {
            ex.printStackTrace();
        }
        return false;
    }

    /**
     * The `uploadFileToServer` function uploads a file with encrypted data to a database server along
     * with the user ID.
     * 
     * @param filePath The `filePath` parameter is a string that represents the path to the file that
     * you want to upload to the server.
     * @param encryptedData The `encryptedData` parameter in the `uploadFileToServer` method is a byte
     * array that contains the encrypted data of the file to be uploaded to the server. This data is
     * inserted into the database as part of the file upload process.
     * @param userId The `userId` parameter in the `uploadFileToServer` method represents the unique
     * identifier of the user who is uploading the file to the server. This user ID is used to
     * associate the uploaded file with the specific user in the database.
     */
    public static void uploadFileToServer(String filePath, byte[] encryptedData, int userId) {
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String insertSql = "INSERT INTO " + ENCRYPTED_FILES_TABLE
                    + " (file_name, encrypted_data, user_id) VALUES (?, ?, ?)";
            try (PreparedStatement insertStatement = connection.prepareStatement(insertSql)) {
                insertStatement.setString(1, Paths.get(filePath).getFileName().toString());
                insertStatement.setBytes(2, encryptedData);
                insertStatement.setInt(3, userId); // Include user ID
                insertStatement.executeUpdate();
            }
        } catch (SQLException ex) {
            ex.printStackTrace();
        }
    }

    /**
     * This Java function downloads an encrypted file from a server based on the file ID and user ID
     * provided.
     * 
     * @param fileId The `fileId` parameter is an integer value that represents the unique identifier
     * of the file that you want to download from the server.
     * @param userId The `userId` parameter in the `downloadEncryptedFileFromServer` method represents
     * the unique identifier of the user who is requesting to download the encrypted file from the
     * server. This parameter is used in the SQL query to ensure that the file being accessed belongs
     * to the specified user.
     * @return A byte array containing the encrypted data of the file with the specified fileId and
     * userId is being returned. If the file is found in the database, its encrypted data is retrieved
     * and returned as a byte array. If the file is not found or an error occurs during the database
     * operation, null is returned.
     */
    public static byte[] downloadEncryptedFileFromServer(int fileId, int userId) {
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                PreparedStatement statement = connection.prepareStatement(
                        "SELECT encrypted_data FROM encrypted_files WHERE file_id = ? AND user_id = ?")) {
            statement.setInt(1, fileId);
            statement.setInt(2, userId);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    return resultSet.getBytes("encrypted_data");
                }
            }
        } catch (SQLException ex) {
            ex.printStackTrace();
        }
        return null;
    }

    /**
     * The function `verifyPassword` compares a hashed password with a newly hashed input password to
     * verify if they match.
     * 
     * @param password The `password` parameter in the `verifyPassword` method is the plain text
     * password that you want to verify against the hashed password.
     * @param hashedPassword The `hashedPassword` parameter in the `verifyPassword` method is the
     * hashed version of the original password. It is the result of applying a cryptographic hash
     * function (in this case, SHA-256) to the original password and then encoding the hashed bytes
     * using Base64 encoding. The purpose of this
     * @return The method `verifyPassword` is returning a boolean value, which indicates whether the
     * input password matches the hashed password after hashing the input password using SHA-256
     * algorithm and encoding it to Base64.
     */
    private static boolean verifyPassword(String password, String hashedPassword) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashedBytes = md.digest(password.getBytes());
        String hashedInputPassword = Base64.getEncoder().encodeToString(hashedBytes);
        return hashedInputPassword.equals(hashedPassword);
    }

    private static String hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashedBytes = md.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(hashedBytes);
    }

    public static boolean doesFileExist(String fileName, int userId) {
        return isFieldExists("file_name", fileName, ENCRYPTED_FILES_TABLE) && isFieldExists("user_id",
                String.valueOf(userId), ENCRYPTED_FILES_TABLE);
    }

    // Method to fetch file data from the server
    public static Object[][] fetchFileData(int userId) {
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                PreparedStatement statement = connection.prepareStatement(
                        "SELECT file_id, file_name FROM encrypted_files WHERE user_id = ?")) {
            statement.setInt(1, userId);
            try (ResultSet resultSet = statement.executeQuery()) {
                List<Object[]> dataList = new ArrayList<>();
                while (resultSet.next()) {
                    int fileId = resultSet.getInt("file_id");
                    String fileName = resultSet.getString("file_name");
                    dataList.add(new Object[] { fileId, fileName });
                }
                Object[][] fileData = new Object[dataList.size()][2];
                for (int i = 0; i < dataList.size(); i++) {
                    fileData[i] = dataList.get(i);
                }
                return fileData;
            }
        } catch (SQLException e) {
            e.printStackTrace();
            return new Object[0][0]; // Return an empty array in case of an error
        }
    }

    public static Object[][] fetchAllUsersData() {
        List<User> userList = new ArrayList<>();

        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                PreparedStatement statement = connection.prepareStatement("SELECT id, username, email FROM users");
                ResultSet resultSet = statement.executeQuery()) {

            while (resultSet.next()) {
                int id = resultSet.getInt("id");
                String username = resultSet.getString("username");
                String email = resultSet.getString("email");
                userList.add(new User(id, username, email));
            }

        } catch (SQLException ex) {
            ex.printStackTrace();
        }

        // Convert the list of users to a two-dimensional array
        Object[][] userData = new Object[userList.size()][3];
        for (int i = 0; i < userList.size(); i++) {
            User user = userList.get(i);
            userData[i][0] = user.getId();
            userData[i][1] = user.getUsername();
            userData[i][2] = user.getEmail();
        }

        return userData;
    }

    public static boolean deleteFileFromServer(int fileId, String fileName) {
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String deleteSql = "DELETE FROM " + ENCRYPTED_FILES_TABLE + " WHERE file_id = ?";
            try (PreparedStatement deleteStatement = connection.prepareStatement(deleteSql)) {
                deleteStatement.setInt(1, fileId);
                int rowsAffected = deleteStatement.executeUpdate();
                return rowsAffected > 0;
            }
        } catch (SQLException ex) {
            ex.printStackTrace();
            return false;
        }
    }

    public static boolean deleteUser(int userId) {
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            // Delete associated rows in the encrypted_files table
            String deleteFilesSql = "DELETE FROM encrypted_files WHERE user_id = ?";
            try (PreparedStatement deleteFilesStatement = connection.prepareStatement(deleteFilesSql)) {
                deleteFilesStatement.setInt(1, userId);
                deleteFilesStatement.executeUpdate();
            }

            // Now delete the user
            String deleteUserSql = "DELETE FROM users WHERE id = ?";
            try (PreparedStatement deleteUserStatement = connection.prepareStatement(deleteUserSql)) {
                deleteUserStatement.setInt(1, userId);
                int rowsAffected = deleteUserStatement.executeUpdate();
                return rowsAffected > 0;
            }
        } catch (SQLException ex) {
            ex.printStackTrace();
            return false;
        }
    }

    // Retrieve sender's email from the user session
    public static String getSenderEmail() {
        return userSession.getEmail();
    }

    // Method to generate a secure download link
    public static String generateDownloadLink(String fileName, int fileId, int userId, String linkExpiryTime) {
        // Generate a unique token for the download link
        String token = UUID.randomUUID().toString();

        // Encrypt the file before sharing
        byte[] encryptedFileData = downloadEncryptedFileFromServer(fileId, userId);

        // Save the encrypted file in the download folder
        String downloadFolderPath = "C:/xampp/htdocs/download/"; // Update with your actual download folder path
        String encryptedFileName = fileName.substring(0, fileName.lastIndexOf('.')) + "_encrypted"
                + fileName.substring(fileName.lastIndexOf('.'));
        String encryptedFilePath = downloadFolderPath + encryptedFileName;

        try {
            // Write the encrypted file data to the file
            Files.write(Paths.get(encryptedFilePath), encryptedFileData);
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Save the token, file name, file id, user id, and link expiry time in the
        // database
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String insertSql = "INSERT INTO download_links (token, file_name, file_id, user_id, link_expiry_time) VALUES (?, ?, ?, ?, ?)";
            try (PreparedStatement insertStatement = connection.prepareStatement(insertSql)) {
                insertStatement.setString(1, token);
                insertStatement.setString(2, encryptedFileName); // Store the encrypted file name
                insertStatement.setInt(3, fileId);
                insertStatement.setInt(4, userId);
                insertStatement.setTimestamp(5,
                        Timestamp.valueOf(LocalDateTime.now().plusMinutes(Long.parseLong(linkExpiryTime))));
                insertStatement.executeUpdate();
            }
        } catch (SQLException ex) {
            ex.printStackTrace();
        }

        // Construct and return the download link
        String baseUrl = "http://localhost/download/"; // Replace with your actual domain
        return baseUrl + token;
    }

    private static final String SENDGRID_API_KEY = "YOUR_API_KEY";

    public static void sendEmail(String receiverEmail, String senderEmail, String message) {
        // Email configuration properties
        Properties properties = new Properties();
        properties.put("mail.smtp.host", "smtp.sendgrid.net");
        properties.put("mail.smtp.port", "587");
        properties.put("mail.smtp.auth", "true");
        properties.put("mail.smtp.starttls.enable", "true");

        // Create a session with authentication
        Session session = Session.getInstance(properties, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication("apikey", SENDGRID_API_KEY);
            }
        });

        try {
            // Create a MimeMessage object
            Message mimeMessage = new MimeMessage(session);
            mimeMessage.setFrom(new InternetAddress(senderEmail));
            mimeMessage.setRecipient(Message.RecipientType.TO, new InternetAddress(receiverEmail));
            mimeMessage.setSubject("File sharing");
            mimeMessage.setText(message);

            // Send the email
            Transport.send(mimeMessage);

            System.out.println("Email sent to: " + receiverEmail);
            System.out.println("Message: " + message);
        } catch (MessagingException e) {
            e.printStackTrace();
            System.err.println("Failed to send email.");
        }
    }
    // Method to fetch IP address
    public static String getIpAddress() {
        try {
            InetAddress localhost = InetAddress.getLocalHost();
            return localhost.getHostAddress();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        return null;
    }
}

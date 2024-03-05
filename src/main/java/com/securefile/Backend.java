/**
 * The `Backend` class in the `com.securefile` package provides functionality for user authentication,
 * file encryption/decryption, database operations, and file management in a secure file storage
 * application.
 */
package com.securefile;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import java.util.Properties;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.sql.Timestamp;

import javax.mail.*;
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
            // Check if keys are already stored in the database
            aesSecretKey = retrieveKey("aes_key");
            desSecretKey = retrieveKey("des_key");

            // If keys are not found in the database, generate new ones
            if (aesSecretKey == null) {
                aesSecretKey = generateKey("AES");
                storeKey("aes_key", aesSecretKey);
            }
            if (desSecretKey == null) {
                desSecretKey = generateKey("DES");
                storeKey("des_key", desSecretKey);
            }
        } catch (GeneralSecurityException | SQLException e) {
            e.printStackTrace();
        }
    }

    // Generate a new secret key
    private static SecretKey generateKey(String algorithm) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
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

    public static byte[] encryptFileData(byte[] fileData) throws GeneralSecurityException, IOException {
        byte[] encryptedDataAES = encrypt(fileData, aesSecretKey, "AES");
        byte[] encryptedDataDES = encrypt(fileData, desSecretKey, "DES");
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(encryptedDataAES);
        outputStream.write(encryptedDataDES);
        return outputStream.toByteArray();
    }

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

    private static byte[] encrypt(byte[] data, SecretKey key, String algorithm) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    private static byte[] decrypt(byte[] encryptedData, SecretKey key, String algorithm)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encryptedData);
    }

    // User login authentication code
    public static boolean authenticateUser(String username, String password) {
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                PreparedStatement statement = connection.prepareStatement(
                        "SELECT id, username, email, password FROM " + USER_TABLE + " WHERE username = ?")) {
            statement.setString(1, username);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    int userId = resultSet.getInt("id");
                    String userEmail = resultSet.getString("email"); // Retrieve user's email
                    String hashedPassword = resultSet.getString("password");
                    if (verifyPassword(password, hashedPassword)) {
                        userSession.loginUser(userId, username, userEmail); // Store user's email in the session
                        return true;
                    }
                }
            }
        } catch (SQLException | NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        }
        return false;
    }

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

    // User Registration code
    public static boolean registerUser(String email, String username, String password) {
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                PreparedStatement statement = connection.prepareStatement(
                        "INSERT INTO " + USER_TABLE + " (email, username, password) VALUES (?, ?, ?)")) {
            statement.setString(1, email); // Add email to registration query
            statement.setString(2, username);
            statement.setString(3, hashPassword(password)); // Hashing the password
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
        boolean isRegistered = false;
        Connection conn = null;
        PreparedStatement stmt = null;
        ResultSet rs = null;

        try {
            // Establish database connection
            conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);

            // Prepare SQL statement to check if the email is registered
            String sql = "SELECT COUNT(*) AS count FROM users WHERE email = ?";
            stmt = conn.prepareStatement(sql);
            stmt.setString(1, email);

            // Execute the query
            rs = stmt.executeQuery();

            // Check if any rows are returned
            if (rs.next()) {
                int count = rs.getInt("count");
                if (count > 0) {
                    // Email is registered
                    isRegistered = true;
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
            // Handle database errors
        } finally {
            // Close the database resources
            try {
                if (rs != null) {
                    rs.close();
                }
                if (stmt != null) {
                    stmt.close();
                }
                if (conn != null) {
                    conn.close();
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }

        return isRegistered;
    }

    // Check if the username is already taken
    public static boolean isUsernameTaken(String username) {
        boolean isTaken = false;
        Connection conn = null;
        PreparedStatement stmt = null;
        ResultSet rs = null;

        try {
            // Establish database connection
            conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);

            // Prepare SQL statement to check if the username is taken
            String sql = "SELECT COUNT(*) AS count FROM users WHERE username = ?";
            stmt = conn.prepareStatement(sql);
            stmt.setString(1, username);

            // Execute the query
            rs = stmt.executeQuery();

            // Check if any rows are returned
            if (rs.next()) {
                int count = rs.getInt("count");
                if (count > 0) {
                    // Username is taken
                    isTaken = true;
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
            // Handle database errors
        } finally {
            // Close the database resources
            try {
                if (rs != null) {
                    rs.close();
                }
                if (stmt != null) {
                    stmt.close();
                }
                if (conn != null) {
                    conn.close();
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }

        return isTaken;
    }


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
        boolean exists = false;
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String sql = "SELECT COUNT(*) AS count FROM " + ENCRYPTED_FILES_TABLE
                    + " WHERE file_name = ? AND user_id = ?";
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setString(1, fileName);
                statement.setInt(2, userId);
                try (ResultSet resultSet = statement.executeQuery()) {
                    if (resultSet.next()) {
                        int count = resultSet.getInt("count");
                        exists = count > 0;
                    }
                }
            }
        } catch (SQLException ex) {
            ex.printStackTrace();
        }
        return exists;
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

        // Save the token, file name, file id, user id, and link expiry time in the
        // database
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String insertSql = "INSERT INTO download_links (token, file_name, file_id, user_id, link_expiry_time) VALUES (?, ?, ?, ?, ?)";
            try (PreparedStatement insertStatement = connection.prepareStatement(insertSql)) {
                insertStatement.setString(1, token);
                insertStatement.setString(2, fileName);
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

    private static final String SENDGRID_API_KEY = "Your_api_key";

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
}

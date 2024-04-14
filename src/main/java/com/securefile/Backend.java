package com.securefile;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

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
import java.util.Random;
import java.util.UUID;
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

import DatabaseManager.DatabaseConfig;
import FileManager.FileDecryptor;
import FileManager.FileEncryptor;
import MailserverManager.EmailConfigLoader;
import UserManager.UserAuthentication;
import UserManager.UserSession;

public class Backend {
    // Database Connection Constants
    private static final String DB_URL = DatabaseConfig.getUrl();
    private static final String DB_USER = DatabaseConfig.getUser();
    private static final String DB_PASSWORD = DatabaseConfig.getPassword();

    // Table Names
    private static final String ENCRYPTED_FILES_TABLE = "encrypted_files";
    private static final String KEY_TABLE = "keys";
    private static final String UPLOADED_FILES_TABLE = "uploaded_files"; 
    private static final String USER_TABLE = "users";

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

    // Store uploaded file in the database
    public static void storeUploadedFile(String fileName, byte[] fileData, int fileId) {
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                PreparedStatement statement = connection
                        .prepareStatement(
                                "INSERT INTO `" + UPLOADED_FILES_TABLE
                                        + "` (file_id,file_name, file_data) VALUES (?, ?, ?)")) {
            statement.setInt(1, fileId);
            statement.setString(2, fileName);
            statement.setBytes(3, fileData);
            statement.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // Method to obtain the file ID from the encrypted_files table
    public static int obtainFileId(String fileName, int userId) {
        int fileId = -1; // Default value indicating failure
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                PreparedStatement statement = connection.prepareStatement(
                        "SELECT file_id FROM "+ ENCRYPTED_FILES_TABLE+" WHERE file_name = ? AND user_id = ?");) {
            statement.setString(1, fileName);
            statement.setInt(2, userId);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    fileId = resultSet.getInt("file_id");
                }
            }
        } catch (SQLException ex) {
            ex.printStackTrace();
        }
        return fileId;
    }

    public static byte[] encryptFileData(byte[] fileData) throws GeneralSecurityException, IOException {
        byte[] encryptedDataAES = FileEncryptor.encrypt(fileData, aesSecretKey, "AES");
        byte[] encryptedDataDES = FileEncryptor.encrypt(fileData, desSecretKey, "DES");
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(encryptedDataAES);
        outputStream.write(encryptedDataDES);
        return outputStream.toByteArray();
    }

    public static byte[] decryptFileData(byte[] encryptedData) throws GeneralSecurityException, IOException {
        int halfLength = encryptedData.length / 2;
        byte[] encryptedDataAES = Arrays.copyOfRange(encryptedData, 0, halfLength);
        byte[] encryptedDataDES = Arrays.copyOfRange(encryptedData, halfLength, encryptedData.length);
        byte[] decryptedDataAES = FileDecryptor.decrypt(encryptedDataAES, aesSecretKey, "AES");
        byte[] decryptedDataDES = FileDecryptor.decrypt(encryptedDataDES, desSecretKey, "DES");
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(decryptedDataAES);
        outputStream.write(decryptedDataDES);
        return outputStream.toByteArray();
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

    public static boolean doesFileExist(String fileName, int userId) {
        return UserAuthentication.isFieldExists("file_name", fileName, ENCRYPTED_FILES_TABLE)
                && UserAuthentication.isFieldExists("user_id",
                        String.valueOf(userId), ENCRYPTED_FILES_TABLE);
    }

    // Method to fetch file data from the server
    public static Object[][] fetchFileData(int userId) {
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                PreparedStatement statement = connection.prepareStatement(
                        "SELECT file_id, file_name FROM " + ENCRYPTED_FILES_TABLE + " WHERE user_id = ?")) {
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

    // Retrieve sender's email from the user session
    public static String getSenderEmail() {
        return userSession.getEmail();
    }

    // Method to generate a secure download link
    public static String generateDownloadLink(String fileName, int fileId, int userId, String linkExpiryTime) {
        // Generate a unique token for the download link
        String token = UUID.randomUUID().toString();
        // Save the token, file name, file id, user id, and link expiry time in
        // thedatabase
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String insertSql = "INSERT INTO download_links (token, file_name, file_id, user_id, link_expiry_time) VALUES (?, ?, ?, ?, ?)";
            try (PreparedStatement insertStatement = connection.prepareStatement(insertSql)) {
                insertStatement.setString(1, token);
                insertStatement.setString(2, fileName); // Store the encrypted file name
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
        String baseUrl = "https://filedownload2003.000webhostapp.com/download.php?token=" + token; // Replace with your
                                                                                                   // actual domain
        return baseUrl;
    }

    public static void sendEmail(String receiverEmail, String senderEmail, String message) {
        message += "\n To download file click above link. \n This link will be expire after some time. ";
        // Email configuration properties
        Properties properties = new Properties();
        properties.put("mail.smtp.host", EmailConfigLoader.getSmtpHost());
        properties.put("mail.smtp.port", EmailConfigLoader.getSmtpPort());
        properties.put("mail.smtp.auth", EmailConfigLoader.getSmtpAuth());
        properties.put("mail.smtp.starttls.enable", EmailConfigLoader.getSmtpStartTls());

        // Create a session with authentication
        Session session = Session.getInstance(properties, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication("apikey", EmailConfigLoader.getSmtpApiKey());
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

        } catch (MessagingException e) {
            e.printStackTrace();
            System.err.println("Failed to send email.");
        }
    }

    public static void sendVerificationEmail(String receiverEmail, int verificationCode) {
        String subject = "Email Verification Code";
        String message = "Your verification code is: " + verificationCode;

        // Email configuration properties
        Properties properties = new Properties();
        properties.put("mail.smtp.host", EmailConfigLoader.getSmtpHost());
        properties.put("mail.smtp.port", EmailConfigLoader.getSmtpPort());
        properties.put("mail.smtp.auth", EmailConfigLoader.getSmtpAuth());
        properties.put("mail.smtp.starttls.enable", EmailConfigLoader.getSmtpStartTls());

        // Create a session with authentication
        Session session = Session.getInstance(properties, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication("apikey", EmailConfigLoader.getSmtpApiKey());
            }
        });

        try {
            // Create a MimeMessage object
            Message mimeMessage = new MimeMessage(session);
            mimeMessage.setFrom(new InternetAddress(EmailConfigLoader.getSmtpUsername()));
            mimeMessage.setRecipient(Message.RecipientType.TO, new InternetAddress(receiverEmail));
            mimeMessage.setSubject(subject);
            mimeMessage.setText(message);

            // Send the email
            Transport.send(mimeMessage);

        } catch (MessagingException e) {
            e.printStackTrace();
            System.err.println("Failed to send email.");
        }
    }

    public static String getIpAddress() {
        try {
            InetAddress localhost = InetAddress.getLocalHost();
            return localhost.getHostAddress();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static boolean emailExists(String email) {
        // SQL query to check the existence of an email
        String query = "SELECT COUNT(email) FROM "+USER_TABLE+" WHERE email = ?";

        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                PreparedStatement statement = connection.prepareStatement(query)) {

            statement.setString(1, email); // Set the email parameter in the SQL query
            ResultSet resultSet = statement.executeQuery(); // Execute the query

            if (resultSet.next()) {
                return resultSet.getInt(1) > 0; // Return true if the count is greater than 0
            }
        } catch (SQLException e) {
            handleException(e); // Handle any SQL exceptions
        }
        return false; // Return false if no email is found or in case of an exception
    }

    public static String sendVerificationCode(String email) {
        // Generate a 5-digit code
        String code = generateCode();
        // Send email (implement using JavaMail or similar)
        sendEmailWithCode(email, code);
        return code;
    }

    public static void updatePassword(String email, String newPassword) {
        // Hash the new password
        String hashedPassword;
        try {
            hashedPassword = hashPassword(newPassword);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Failed to hash password: " + e.getMessage());
            return; // Exit the method if hashing fails
        }

        // SQL update statement to update the user's password
        String query = "UPDATE users SET password = ? WHERE email = ?";

        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                PreparedStatement statement = connection.prepareStatement(query)) {

            statement.setString(1, hashedPassword); // Set the hashed password parameter
            statement.setString(2, email); // Set the email parameter
            int updatedRows = statement.executeUpdate(); // Execute the update statement

            // Check if the update was successful
            if (updatedRows > 0) {
                System.out.println("Password updated successfully.");
            } else {
                System.out.println("No user found with the provided email.");
            }
        } catch (SQLException e) {
            handleException(e); // Handle any SQL exceptions
        }
    }

    private static String hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashedBytes = md.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(hashedBytes);
    }

    public static void sendEmailWithCode(String email, String code) {
        String subject = "Password Verification Code";
        String message = "Your verification code is: " + code;

        // Email configuration properties
        Properties properties = new Properties();
        properties.put("mail.smtp.host", EmailConfigLoader.getSmtpHost());
        properties.put("mail.smtp.port", EmailConfigLoader.getSmtpPort());
        properties.put("mail.smtp.auth", EmailConfigLoader.getSmtpAuth());
        properties.put("mail.smtp.starttls.enable", EmailConfigLoader.getSmtpStartTls());

        // Create a session with authentication
        Session session = Session.getInstance(properties, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication("apikey",EmailConfigLoader.getSmtpApiKey());
            }
        });

        try {
            // Create a MimeMessage object
            Message mimeMessage = new MimeMessage(session);
            mimeMessage.setFrom(new InternetAddress(EmailConfigLoader.getSmtpUsername()));
            mimeMessage.setRecipient(Message.RecipientType.TO, new InternetAddress(email));
            mimeMessage.setSubject(subject);
            mimeMessage.setText(message);

            // Send the email
            Transport.send(mimeMessage);
            System.out.println("Email sent successfully to: " + email);

        } catch (MessagingException e) {
            e.printStackTrace();
            System.err.println("Failed to send email to: " + email);
        }
    }

    private static String generateCode() {
        return String.valueOf(new Random().nextInt(89999) + 10000); // Generates a 5-digit random number
    }
}

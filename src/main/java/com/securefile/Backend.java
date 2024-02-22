package com.securefile;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Backend {
    // Database Connection Constants
    private static final String DB_URL = "jdbc:mysql://localhost:3306/filedatabase";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = ""; // Replace with your database password

    // Encryption Keys
    private static SecretKey aesSecretKey;
    private static SecretKey desSecretKey;

    // Table Names
    private static final String USER_TABLE = "users";
    private static final String ENCRYPTED_FILES_TABLE = "encrypted_files";

    public static void initializeEncryptionKeys() {
        try {
            generateAESKey();
            generateDESKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private static void generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        aesSecretKey = keyGen.generateKey();
    }

    private static void generateDESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        keyGen.init(56);
        desSecretKey = keyGen.generateKey();
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
                PreparedStatement statement = connection
                        .prepareStatement("SELECT * FROM " + USER_TABLE + " WHERE username = ? AND password = ?")) {
            statement.setString(1, username);
            statement.setString(2, password);
            try (ResultSet resultSet = statement.executeQuery()) {
                return resultSet.next(); // If a row is found, authentication succeeds
            }
        } catch (SQLException ex) {
            ex.printStackTrace();
            return false;
        }
    }

    // User Registration code
    public static boolean registerUser(String fullName, String username, String password) {
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                PreparedStatement statement = connection.prepareStatement(
                        "INSERT INTO " + USER_TABLE + " (full_name, username, password) VALUES (?, ?, ?)")) {
            statement.setString(1, fullName);
            statement.setString(2, username);
            statement.setString(3, password);
            int rowsAffected = statement.executeUpdate();
            return rowsAffected > 0; // If at least one row is affected, registration succeeds
        } catch (SQLException ex) {
            ex.printStackTrace();
            return false;
        }
    }

    public static void uploadFileToServer(String filePath, byte[] encryptedData) {
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String insertSql = "INSERT INTO " + ENCRYPTED_FILES_TABLE + " (file_name, encrypted_data) VALUES (?, ?)";
            try (PreparedStatement insertStatement = connection.prepareStatement(insertSql)) {
                insertStatement.setString(1, Paths.get(filePath).getFileName().toString());
                insertStatement.setBytes(2, encryptedData);
                insertStatement.executeUpdate();
            }
        } catch (SQLException ex) {
            ex.printStackTrace();
        }
    }

    public static byte[] downloadFileFromServer() {
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String sql = "SELECT * FROM " + ENCRYPTED_FILES_TABLE;
            try (Statement statement = connection.createStatement();
                    ResultSet resultSet = statement.executeQuery(sql)) {
                if (resultSet.next()) {
                    return resultSet.getBytes("encrypted_data");
                }
            }
        } catch (SQLException ex) {
            ex.printStackTrace();
        }
        return null;
    }
}

package com.securefile;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class Main {
    // Gui Variable
    private static JFrame loginFrame;
    private static JTextField usernameField;
    private static JPasswordField passwordField;
    private static JFrame registrationFrame;
    private static JTextField regFullNameField;
    private static JTextField regUsernameField;
    private static JPasswordField regPasswordField;
    private static JFrame fileUploadFrame;
    private static JLabel uploadLabel;
    // Add database connection Variable
    private static final String DB_URL = "jdbc:mysql://localhost:3306/filedatabase";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "";

    private static SecretKey aesSecretKey;
    private static SecretKey desSecretKey;
    private static final String USER_TABLE = "users";

    public static void main(String[] args) {
        SwingUtilities.invokeLater(Main::createAndShowLoginGUI);
    }

    // GUI Components & Functions
    private static void createAndShowLoginGUI() {
        // Create the main login frame
        loginFrame = new JFrame("Login");
        loginFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        loginFrame.setSize(500, 500);
        loginFrame.setLayout(new GridBagLayout());

        // Create login components
        JLabel loginLabel = new JLabel("LOGIN");
        loginLabel.setFont(new Font("Arial", Font.BOLD, 20));
        usernameField = new JTextField(20);
        passwordField = new JPasswordField(20);
        JButton loginButton = new JButton("Login");
        JButton registerButton = new JButton("Don't have an account? Register");

        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(10, 10, 10, 10);
        c.gridwidth = 2;
        c.gridx = 0;
        c.gridy = 0;
        c.anchor = GridBagConstraints.CENTER;
        loginFrame.add(loginLabel, c);

        c.gridwidth = 1;
        c.gridy = 1;
        c.anchor = GridBagConstraints.CENTER;
        loginFrame.add(new JLabel("Username:"), c);
        c.gridy = 2;
        loginFrame.add(new JLabel("Password:"), c);
        c.gridwidth = 2;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.gridy = 1;
        c.gridx = 1;
        loginFrame.add(usernameField, c);
        c.gridy = 2;
        loginFrame.add(passwordField, c);
        c.gridy = 3;
        c.gridx = 0;
        c.gridwidth = 2;
        loginFrame.add(loginButton, c);
        c.gridy = 4;
        loginFrame.add(registerButton, c);

        // Create the registration frame
        registrationFrame = new JFrame("Registration");
        registrationFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        registrationFrame.setSize(500, 500);
        registrationFrame.setLayout(new GridBagLayout());

        // Create registration components
        JLabel registerLabel = new JLabel("Register");
        regFullNameField = new JTextField(20);
        regUsernameField = new JTextField(20);
        regPasswordField = new JPasswordField(20);
        JButton regRegisterButton = new JButton("Register");
        JButton backButton = new JButton("Back to Login");

        c.insets = new Insets(10, 10, 10, 10);
        c.gridwidth = 2;
        c.gridx = 0;
        c.gridy = 0;
        c.anchor = GridBagConstraints.CENTER;
        registrationFrame.add(registerLabel, c);

        c.gridwidth = 1;
        c.gridy = 1;
        c.anchor = GridBagConstraints.CENTER;
        registrationFrame.add(new JLabel("Full Name:"), c);
        c.gridy = 2;
        registrationFrame.add(new JLabel("Username:"), c);
        c.gridy = 3;
        registrationFrame.add(new JLabel("New Password:"), c);
        c.gridwidth = 2;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.gridy = 1;
        c.gridx = 1;
        registrationFrame.add(regFullNameField, c);
        c.gridy = 2;
        registrationFrame.add(regUsernameField, c);
        c.gridy = 3;
        registrationFrame.add(regPasswordField, c);
        c.gridy = 4;
        c.gridx = 0;
        c.gridwidth = 2;
        registrationFrame.add(regRegisterButton, c);
        c.gridy = 5;
        registrationFrame.add(backButton, c);

        // Create the file upload frame
        fileUploadFrame = new JFrame("File Upload");
        fileUploadFrame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        fileUploadFrame.setSize(500, 500);
        fileUploadFrame.setLayout(new GridBagLayout());

        JLabel plusSignLabel = new JLabel(new ImageIcon("src/main/resources/plus.png")); // Replace "plus.png" with
        // your plus sign image
        // file
        uploadLabel = new JLabel("Select File");
        uploadLabel.setFont(new Font("Arial", Font.BOLD, 12));
        JButton encryptButton = new JButton("Upload file");
        JButton decryptButton = new JButton("Download");
        JButton logoutButton = new JButton("Logout"); // Adding a logout button

        c.insets = new Insets(10, 10, 10, 10);
        c.gridwidth = 2;
        c.gridx = 0;
        c.gridy = 0;
        c.anchor = GridBagConstraints.CENTER;
        fileUploadFrame.add(plusSignLabel, c);

        c.gridy = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.CENTER;
        fileUploadFrame.add(uploadLabel, c);

        c.gridy = 2;
        c.anchor = GridBagConstraints.CENTER;
        fileUploadFrame.add(encryptButton, c);

        c.gridy = 3;
        c.anchor = GridBagConstraints.CENTER;
        fileUploadFrame.add(decryptButton, c);

        c.gridy = 4;
        c.anchor = GridBagConstraints.CENTER;
        fileUploadFrame.add(logoutButton, c); // Adding logout button to the frame

        // Initially, hide the frames
        registrationFrame.setVisible(false);
        fileUploadFrame.setVisible(false);

        /***** Backend Code *******/

        // Action listeners
        loginButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String username = usernameField.getText();
                char[] passwordChars = passwordField.getPassword();
                String password = new String(passwordChars);

                if (authenticateUser(username, password)) {
                    // Login successful, show file upload frame
                    fileUploadFrame.setVisible(true);
                    loginFrame.setVisible(false);
                } else {
                    JOptionPane.showMessageDialog(loginFrame, "Invalid username or password", "Login Error",
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        // ActionListener for logout button
        logoutButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // Close file upload frame
                fileUploadFrame.dispose();

                // Show login frame
                loginFrame.setVisible(true);
            }
        });

        registerButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                registrationFrame.setVisible(true);
                loginFrame.setVisible(false);
            }
        });

        regRegisterButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String fullName = regFullNameField.getText();
                String username = regUsernameField.getText();
                char[] passwordChars = regPasswordField.getPassword();
                String password = new String(passwordChars);

                if (registerUser(fullName, username, password)) {
                    JOptionPane.showMessageDialog(registrationFrame, "Registration successful", "Registration",
                            JOptionPane.INFORMATION_MESSAGE);
                    registrationFrame.setVisible(false);
                    loginFrame.setVisible(true);
                } else {
                    JOptionPane.showMessageDialog(registrationFrame, "Registration failed", "Registration Error",
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        backButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                loginFrame.setVisible(true);
                registrationFrame.setVisible(false);
            }
        });

        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String filePath = (String) plusSignLabel.getClientProperty("filePath");

                if (filePath != null && !filePath.isEmpty()) {
                    try {
                        File selectedFile = new File(filePath);
                        byte[] fileData = Files.readAllBytes(selectedFile.toPath());

                        // Generate AES key
                        generateAESKey();

                        // Encrypt the file data using AES
                        byte[] encryptedDataAES = encryptAES(fileData);

                        // Generate DES key
                        generateDESKey();

                        // Encrypt the file data using DES
                        byte[] encryptedDataDES = encryptDES(fileData);

                        // Combine both encrypted data
                        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                        outputStream.write(encryptedDataAES);
                        outputStream.write(encryptedDataDES);
                        byte[] combinedEncryptedData = outputStream.toByteArray();

                        // Save the combined encrypted data to a new file
                        Path encryptedFilePath = Paths.get("encrypted_file.txt");
                        Files.write(encryptedFilePath, combinedEncryptedData, StandardOpenOption.CREATE);

                        // Upload the file and encrypted data to the server
                        uploadFileToServer(filePath, combinedEncryptedData);

                        uploadLabel.setText("File Encrypted and Uploaded to Server");
                    } catch (IOException | GeneralSecurityException ex) {
                        ex.printStackTrace();
                        uploadLabel.setText("Error during encryption.");
                    }
                } else {
                    uploadLabel.setText("No file selected for encryption.");
                }
            }
        });

        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // Download the encrypted file from the server
                byte[] combinedEncryptedData = downloadFileFromServer();

                if (combinedEncryptedData != null) {
                    try {
                        // Split the combined encrypted data into AES and DES encrypted data
                        int halfLength = combinedEncryptedData.length / 2;
                        byte[] encryptedDataAES = Arrays.copyOfRange(combinedEncryptedData, 0, halfLength);
                        byte[] encryptedDataDES = Arrays.copyOfRange(combinedEncryptedData, halfLength,
                                combinedEncryptedData.length);

                        // Decrypt the AES encrypted data
                        byte[] decryptedDataAES = decryptAES(encryptedDataAES);

                        // Decrypt the DES encrypted data
                        byte[] decryptedDataDES = decryptDES(encryptedDataDES);

                        // Save the decrypted data to a new file
                        Path decryptedFilePath = Paths.get("decrypted_file.txt");
                        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                        outputStream.write(decryptedDataAES);
                        outputStream.write(decryptedDataDES);
                        byte[] combinedDecryptedData = outputStream.toByteArray();
                        Files.write(decryptedFilePath, combinedDecryptedData, StandardOpenOption.CREATE);

                        uploadLabel.setText("File Decrypted and Saved: " + decryptedFilePath.getFileName());
                    } catch (GeneralSecurityException | IOException ex) {
                        ex.printStackTrace();
                        uploadLabel.setText("Error during decryption.");
                    }
                } else {
                    uploadLabel.setText("Error: Unable to download the encrypted file from the server.");
                }
            }
        });

        plusSignLabel.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setFileFilter(new FileNameExtensionFilter("Text Files", "txt"));
                int result = fileChooser.showOpenDialog(fileUploadFrame);
                if (result == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = fileChooser.getSelectedFile();

                    // Store the file path in a variable
                    String filePath = selectedFile.getAbsolutePath();

                    // Update the uploadLabel
                    uploadLabel.setText("File Selected: " + selectedFile.getName());

                    // Set the file path in the plusSignLabel's client property
                    plusSignLabel.putClientProperty("filePath", filePath);
                }
            }
        });

        // Display the login frame
        loginFrame.setVisible(true);
    }

    // User login authentication code
    private static boolean authenticateUser(String username, String password) {
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

    // User Registeration code
    private static boolean registerUser(String fullName, String username, String password) {
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

    private static byte[] encryptAES(byte[] data) throws GeneralSecurityException {
        return encrypt(data, aesSecretKey, "AES");
    }

    private static byte[] encryptDES(byte[] data) throws GeneralSecurityException {
        return encrypt(data, desSecretKey, "DES");
    }

    private static byte[] decryptAES(byte[] encryptedData) throws GeneralSecurityException {
        return decrypt(encryptedData, aesSecretKey, "AES");
    }

    private static byte[] decryptDES(byte[] encryptedData) throws GeneralSecurityException {
        return decrypt(encryptedData, desSecretKey, "DES");
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

    private static void uploadFileToServer(String filePath, byte[] encryptedData) {
        try {
            Connection connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/filedatabase", "root", "");
            String insertSql = "INSERT INTO encrypted_files (file_name, encrypted_data) VALUES (?, ?)";
            PreparedStatement insertStatement = connection.prepareStatement(insertSql);
            insertStatement.setString(1, Paths.get(filePath).getFileName().toString());
            insertStatement.setBytes(2, encryptedData);
            insertStatement.executeUpdate();
            insertStatement.close();
            connection.close();
        } catch (SQLException ex) {
            ex.printStackTrace();
        }
    }

    private static byte[] downloadFileFromServer() {
        try {
            Connection connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/filedatabase", "root", "");
            String sql = "SELECT * FROM encrypted_files";
            Statement statement = connection.createStatement();
            ResultSet resultSet = statement.executeQuery(sql);
            if (resultSet.next()) {
                return resultSet.getBytes("encrypted_data");
            }
            resultSet.close();
            statement.close();
            connection.close();
        } catch (SQLException ex) {
            ex.printStackTrace();
        }
        return null;
    }
}

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
import javax.crypto.spec.IvParameterSpec;
import javax.swing.filechooser.FileNameExtensionFilter;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import javax.crypto.SecretKey;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.storage.*;

public class Main {

    private static JFrame loginFrame;
    private static JTextField usernameField;
    private static JPasswordField passwordField;
    private static JFrame registrationFrame;
    private static JTextField regFullNameField;
    private static JTextField regUsernameField;
    private static JPasswordField regPasswordField;
    private static JFrame fileUploadFrame;
    private static JLabel uploadLabel;

    private static SecretKey aesSecretKey;
    private static SecretKey desSecretKey;

    // private static final String encryptedFilePath = "encrypted_file.txt";
    // private static final String decryptedFilePath = "decrypted_file.txt";

    private static final String BUCKET_NAME = "your_bucket_name"; // Replace with your GCS bucket name

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> createAndShowLoginGUI());
    }

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
        uploadLabel = new JLabel("Upload File");
        uploadLabel.setFont(new Font("Arial", Font.BOLD, 12));
        JButton encryptButton = new JButton("Encrypt");
        JButton decryptButton = new JButton("Decrypt");

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

        // Initially, hide the frames
        registrationFrame.setVisible(false);
        fileUploadFrame.setVisible(false);

        // Action listeners
        loginButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // TODO: Add your login logic here
                handleLogin();
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
                // TODO: Add your registration logic here
                handleRegistration();
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

                        // Save the encrypted data to a new file
                        Path encryptedFilePathAES = Paths.get("encrypted_file_aes.txt");
                        Files.write(encryptedFilePathAES, encryptedDataAES, StandardOpenOption.CREATE);

                        uploadLabel.setText("File Encrypted (AES) and Saved: " + encryptedFilePathAES.getFileName());

                        // Generate DES key
                        generateDESKey();

                        // Encrypt the file data using DES
                        byte[] encryptedDataDES = encryptDES(fileData);

                        // Save the encrypted data to a new file
                        Path encryptedFilePathDES = Paths.get("encrypted_file_des.txt");
                        Files.write(encryptedFilePathDES, encryptedDataDES, StandardOpenOption.CREATE);

                        uploadLabel.setText("File Encrypted (DES) and Saved: " + encryptedFilePathDES.getFileName());
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
                try {
                    // Read the encrypted data from the file (AES)
                    byte[] encryptedDataAES = Files.readAllBytes(Paths.get("encrypted_file_aes.txt"));

                    // Decrypt the data (AES)
                    byte[] decryptedDataAES = decryptAES(encryptedDataAES);

                    // Save the decrypted data to a new file
                    Path decryptedFilePathAES = Paths.get("decrypted_file_aes.txt");
                    Files.write(decryptedFilePathAES, decryptedDataAES, StandardOpenOption.CREATE);

                    uploadLabel.setText("File Decrypted (AES) and Saved: " + decryptedFilePathAES.getFileName());

                    // Read the encrypted data from the file (DES)
                    byte[] encryptedDataDES = Files.readAllBytes(Paths.get("encrypted_file_des.txt"));

                    // Decrypt the data (DES)
                    byte[] decryptedDataDES = decryptDES(encryptedDataDES);

                    // Save the decrypted data to a new file
                    Path decryptedFilePathDES = Paths.get("decrypted_file_des.txt");
                    Files.write(decryptedFilePathDES, decryptedDataDES, StandardOpenOption.CREATE);

                    uploadLabel.setText("File Decrypted (DES) and Saved: " + decryptedFilePathDES.getFileName());

                } catch (IOException | GeneralSecurityException ex) {
                    ex.printStackTrace();
                    uploadLabel.setText("Error during decryption.");
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
                    uploadLabel.setText("File Uploaded: " + selectedFile.getName());

                    // Set the file path in the plusSignLabel's client property
                    plusSignLabel.putClientProperty("filePath", filePath);

                    // Encrypt and upload the file to Google Cloud Storage
                    encryptAndUploadFile(filePath);
                }
            }
        });

        // Display the login frame
        loginFrame.setVisible(true);
    }

    private static void handleLogin() {
        // TODO: Add your login validation logic here
        // For now, just switch to file upload frame
        fileUploadFrame.setVisible(true);
        loginFrame.setVisible(false);
    }

    private static void handleRegistration() {
        // TODO: Add your registration logic here
        // For now, just switch to file upload frame
        fileUploadFrame.setVisible(true);
        registrationFrame.setVisible(false);
    }


    private static void generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        SecureRandom secureRandom = new SecureRandom();
        keyGen.init(256, secureRandom);
        aesSecretKey = keyGen.generateKey();
    }

    private static void generateDESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        SecureRandom secureRandom = new SecureRandom();
        keyGen.init(56, secureRandom);
        desSecretKey = keyGen.generateKey();
    }

    private static byte[] encryptAES(byte[] data) throws GeneralSecurityException {
        return encrypt(data, aesSecretKey, "AES/CBC/PKCS5Padding");
    }

    private static byte[] decryptAES(byte[] data) throws GeneralSecurityException {
        return decrypt(data, aesSecretKey, "AES/CBC/PKCS5Padding");
    }

    private static byte[] encryptDES(byte[] data) throws GeneralSecurityException {
        return encrypt(data, desSecretKey, "DES/CBC/PKCS5Padding");
    }

    private static byte[] decryptDES(byte[] data) throws GeneralSecurityException {
        return decrypt(data, desSecretKey, "DES/CBC/PKCS5Padding");
    }

    private static byte[] encrypt(byte[] data, SecretKey key, String algorithm) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(algorithm);

        // Generate Initialization Vector (IV)
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[cipher.getBlockSize()];
        secureRandom.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        // Combine IV and encrypted data
        byte[] encryptedData = cipher.doFinal(data);
        byte[] result = new byte[iv.length + encryptedData.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encryptedData, 0, result, iv.length, encryptedData.length);

        return result;
    }

    private static byte[] decrypt(byte[] data, SecretKey key, String algorithm) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(algorithm);

        // Extract Initialization Vector (IV) from the encrypted data
        IvParameterSpec ivSpec = new IvParameterSpec(Arrays.copyOfRange(data, 0, cipher.getBlockSize()));

        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        return cipher.doFinal(Arrays.copyOfRange(data, cipher.getBlockSize(), data.length));
    }


    private static void handleFileUpload(String filePath, byte[] encryptedData) {
        try {
            // Set up Google Cloud Storage client
            Storage storage = StorageOptions.newBuilder()
                    .setCredentials(GoogleCredentials.fromStream(new FileInputStream("src/main/java/com/securefile/Main.java/credentials.json")))
                    .setProjectId("your_project_id")
                    .build()
                    .getService();

            // Generate a unique object name (you may customize this)
            String objectName = "encrypted_files/" + System.currentTimeMillis() + "_"
                    + Paths.get(filePath).getFileName();

            // Upload the encrypted file to Google Cloud Storage
            BlobId blobId = BlobId.of(BUCKET_NAME, objectName);
            BlobInfo blobInfo = BlobInfo.newBuilder(blobId).setContentType("application/octet-stream").build();
            storage.create(blobInfo, encryptedData);

            // Display success message or perform additional actions
            uploadLabel.setText("File Encrypted and Uploaded to Cloud: " + objectName);
        } catch (IOException | StorageException ex) {
            ex.printStackTrace();
            uploadLabel.setText("Error during file upload to Cloud Storage.");
        }
    }

    private static void encryptAndUploadFile(String filePath) {
        try {
            File selectedFile = new File(filePath);
            byte[] fileData = Files.readAllBytes(selectedFile.toPath());

            // Generate AES key
            generateAESKey();

            // Encrypt the file data
            byte[] encryptedData = encryptAES(fileData);

            // Upload the encrypted file to Google Cloud Storage
            handleFileUpload(filePath, encryptedData);
        } catch (IOException | GeneralSecurityException ex) {
            ex.printStackTrace();
            uploadLabel.setText("Error during encryption and file upload to Cloud Storage.");
        }
    }

}

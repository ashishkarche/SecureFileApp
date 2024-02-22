package com.securefile;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.security.GeneralSecurityException;

public class GUI {
    private static JFrame loginFrame;
    private static JTextField usernameField;
    private static JPasswordField passwordField;
    private static JFrame registrationFrame;
    private static JTextField regFullNameField;
    private static JTextField regUsernameField;
    private static JPasswordField regPasswordField;
    private static JFrame fileUploadFrame;
    private static JLabel uploadLabel;

    public static void createAndShowLoginGUI() {
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

        JLabel plusSignLabel = new JLabel(new ImageIcon("src/main/resources/plus.png"));
        uploadLabel = new JLabel("Select File");
        uploadLabel.setFont(new Font("Arial", Font.BOLD, 12));
        JButton encryptButton = new JButton("Upload file");
        JButton decryptButton = new JButton("Download");
        JButton logoutButton = new JButton("Logout");

        c.insets = new Insets(10, 10, 20, 10);
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

        c.insets = new Insets(10, 10, 10, 10);
        c.gridwidth = 1;
        c.gridx = 4;
        c.gridy = 0;
        c.anchor = GridBagConstraints.NORTHWEST;
        fileUploadFrame.add(logoutButton, c);

        // Initially, hide the frames
        registrationFrame.setVisible(false);
        fileUploadFrame.setVisible(false);

        /***** Backend Code *******/
        Backend.initializeEncryptionKeys();

        // Action listeners
        loginButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String username = usernameField.getText();
                char[] passwordChars = passwordField.getPassword();
                String password = new String(passwordChars);

                if (Backend.authenticateUser(username, password)) {
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

                if (Backend.registerUser(fullName, username, password)) {
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

                        // Encrypt the file data and upload to server
                        byte[] encryptedData = Backend.encryptFileData(fileData);
                        Backend.uploadFileToServer(filePath, encryptedData);

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
                byte[] encryptedData = Backend.downloadFileFromServer();

                if (encryptedData != null) {
                    try {
                        // Decrypt the encrypted data
                        byte[] decryptedData = Backend.decryptFileData(encryptedData);

                        // Choose a location to save the decrypted file
                        JFileChooser fileChooser = new JFileChooser();
                        fileChooser.setDialogTitle("Save Decrypted File");
                        int userSelection = fileChooser.showSaveDialog(null);

                        if (userSelection == JFileChooser.APPROVE_OPTION) {
                            File decryptedFile = fileChooser.getSelectedFile();

                            // Write the decrypted data to the selected file
                            Files.write(decryptedFile.toPath(), decryptedData);

                            uploadLabel.setText("File Decrypted and Saved: " + decryptedFile.getAbsolutePath());
                        } else {
                            uploadLabel.setText("Decryption canceled or file not saved.");
                        }
                    } catch (GeneralSecurityException | IOException ex) {
                        ex.printStackTrace();
                        uploadLabel.setText("Error during decryption or file saving.");
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
}
/**
 * The `GUI` class in the `com.securefile` package contains methods to create and display graphical
 * user interfaces for login, registration, dashboard, and file upload functionalities.
 */
package com.securefile;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Paths;

import javax.swing.filechooser.FileNameExtensionFilter;

import FileManager.FileManagement;
import UserManager.UserAuthentication;
import UserManager.UserSession;

import java.util.Random;
import java.util.TimerTask;
import java.util.concurrent.atomic.AtomicBoolean;
import java.security.GeneralSecurityException;
import java.util.Timer;

public class GUI {
    public static JFrame loginFrame;
    public static JTextField usernameField;
    public static JPasswordField passwordField;
    private static JFrame registrationFrame;
    private static JTextField regEmailField;
    private static JTextField regUsernameField;
    private static JPasswordField regPasswordField;
    public static JFrame fileUploadFrame;
    private static JLabel uploadLabel;
    private static JLabel passwordLengthLabel;
    private static JLabel internetStatusLabel;
    public static String ImagePath = "src/main/resources/plus.png"; // Replace Image Path with your Image path

    // Create a flag to track email verification
    public static AtomicBoolean emailVerified = new AtomicBoolean(false);

    public static void createAndShowLoginGUI() {

        // Create the main login frame
        loginFrame = new JFrame("Login");
        loginFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        loginFrame.setSize(500, 500);
        loginFrame.setLayout(new GridBagLayout());

        // Add InternetStatusIndicator to the header area
        JRootPane rootPane = loginFrame.getRootPane();
        JMenuBar menuBar = new JMenuBar();
        internetStatusLabel = new JLabel("Internet status: Checking...");
        menuBar.add(Box.createHorizontalGlue()); // Align status indicator to the right
        menuBar.add(internetStatusLabel);
        rootPane.setJMenuBar(menuBar);

        // Create login components
        JLabel loginLabel = new JLabel("LOGIN");
        loginLabel.setFont(new Font("Arial", Font.BOLD, 20));
        usernameField = new JTextField(20);
        passwordField = new JPasswordField(20);
        JButton loginButton = new JButton("Login");
        JButton registerButton = new JButton("Don't have an account? Register");

        // Create dropdown for user/admin selection
        String[] userTypes = { "User", "Admin" };
        JComboBox<String> userTypeComboBox = new JComboBox<>(userTypes);

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
        c.gridy = 3;
        loginFrame.add(new JLabel("User Type:"), c);
        c.gridwidth = 2;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.gridy = 1;
        c.gridx = 1;
        loginFrame.add(usernameField, c);
        c.gridy = 2;
        loginFrame.add(passwordField, c);
        c.gridy = 3;
        loginFrame.add(userTypeComboBox, c);
        c.gridy = 4;
        c.gridx = 0;
        c.gridwidth = 2;
        loginFrame.add(loginButton, c);
        c.gridy = 5;
        loginFrame.add(registerButton, c);
        JButton forgetPasswordButton = new JButton("Forgot Password"); // Define forgetPasswordButton
        c.insets = new Insets(10, 10, 10, 10);
        c.gridwidth = 2;
        c.gridx = 0;
        c.gridy = 6; // Adjust the gridy position according to your layout
        loginFrame.add(forgetPasswordButton, c);

        // Create the registration frame
        registrationFrame = new JFrame("Registration");
        registrationFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        registrationFrame.setSize(500, 500);
        registrationFrame.setLayout(new GridBagLayout());

        // Create registration components
        JLabel registerLabel = new JLabel("Register");
        regEmailField = new JTextField(20);
        regUsernameField = new JTextField(20);
        regPasswordField = new JPasswordField(20);
        JButton regRegisterButton = new JButton("Register");
        JButton backButton = new JButton("Back to Login");
        JButton emailVerifyButton = new JButton("Verify Email");

        passwordLengthLabel = new JLabel();

        c.insets = new Insets(10, 10, 10, 10);
        c.gridwidth = 2;
        c.gridx = 0;
        c.gridy = 0;
        c.anchor = GridBagConstraints.CENTER;
        registrationFrame.add(registerLabel, c);

        c.gridwidth = 1;
        c.gridy = 1;
        c.anchor = GridBagConstraints.CENTER;
        registrationFrame.add(new JLabel("Email:"), c);
        c.gridy = 2;
        registrationFrame.add(new JLabel("Username:"), c);
        c.gridy = 3;
        registrationFrame.add(new JLabel("New Password:"), c);
        c.gridwidth = 2;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.gridy = 1;
        c.gridx = 1;
        registrationFrame.add(regEmailField, c);
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
        c.gridy = 6;
        registrationFrame.add(passwordLengthLabel, c);
        c.gridy = 7;
        registrationFrame.add(emailVerifyButton, c);

        // Create the file upload frame
        fileUploadFrame = new JFrame("File Upload");
        fileUploadFrame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        fileUploadFrame.setSize(500, 500);
        fileUploadFrame.setLayout(new GridBagLayout());

        JLabel plusSignLabel = new JLabel(new ImageIcon(ImagePath));
        uploadLabel = new JLabel("Select File");
        uploadLabel.setFont(new Font("Arial", Font.BOLD, 12));
        JButton encryptButton = new JButton("Upload file");
        JButton backButton1 = new JButton("Back to Dashboard");

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
        c.gridy = 3; // Adjust the gridy position according to your layout
        fileUploadFrame.add(backButton1, c);

        // Initially, hide the frames
        registrationFrame.setVisible(false);
        fileUploadFrame.setVisible(false);

        Backend.initializeEncryptionKeys();

        // Action listeners
        loginButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String username = usernameField.getText();
                char[] passwordChars = passwordField.getPassword();
                String password = new String(passwordChars);
                String userType = (String) userTypeComboBox.getSelectedItem();

                // Get the IP address
                String ipAddress = Backend.getIpAddress();

                if (userType.equals("User")) {
                    // Perform user login authentication
                    if (UserAuthentication.authenticateUser(username, password, ipAddress)) {
                        // Login successful, show user dashboard
                        userDashboard.createAndShowDashboardGUI(username);
                        loginFrame.setVisible(false);
                    } else {
                        JOptionPane.showMessageDialog(loginFrame, "Invalid username or password", "Login Error",
                                JOptionPane.ERROR_MESSAGE);
                    }
                } else if (userType.equals("Admin")) {
                    // Perform admin login authentication
                    if (Backend.authenticateAdmin(username, password)) {
                        // Admin login successful, show admin dashboard
                        adminDashboard.createAndShowAdminDashboardGUI();
                        loginFrame.setVisible(false);
                    } else {
                        JOptionPane.showMessageDialog(loginFrame, "Invalid admin credentials", "Login Error",
                                JOptionPane.ERROR_MESSAGE);
                    }
                }
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

                if (!emailVerified.get()) {
                    // Display an alert if email is not verified
                    JOptionPane.showMessageDialog(registrationFrame, "Please verify your email address.",
                            "Email Verification Required",
                            JOptionPane.WARNING_MESSAGE);
                    return;
                }
                String email = regEmailField.getText(); // Retrieve email
                String username = regUsernameField.getText();
                char[] passwordChars = regPasswordField.getPassword();
                String password = new String(passwordChars);
                String ipAddress = Backend.getIpAddress();

                // Check if the email is already registered
                if (UserAuthentication.isEmailRegistered(email)) {
                    JOptionPane.showMessageDialog(registrationFrame, "Email already registered", "Registration Error",
                            JOptionPane.ERROR_MESSAGE);
                    return;
                }

                // Check if the username is already taken
                if (UserAuthentication.isUsernameTaken(username)) {
                    JOptionPane.showMessageDialog(registrationFrame, "Username already taken", "Registration Error",
                            JOptionPane.ERROR_MESSAGE);
                    return;
                }

                if (password.length() != 8) { // Check password length
                    passwordLengthLabel.setText("Password should be 8 characters long");
                    return;
                } else {
                    passwordLengthLabel.setText(""); // Clear password length message
                }

                // Register the user
                if (UserAuthentication.registerUser(email, username, password, ipAddress)) { // Register user with email
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

        // Add action listener for the Forgot Password button
        forgetPasswordButton.addActionListener(e -> {
            // Prompt user to enter their email
            String email = JOptionPane.showInputDialog(loginFrame, "Enter your register email:", "Forgot Password",
                    JOptionPane.PLAIN_MESSAGE);
            if (email != null && !email.isEmpty()) {
                // Check if email exists in the database
                if (Backend.emailExists(email)) {
                    boolean codeVerified = false;
                    while (!codeVerified) {
                        // Send verification code to the email
                        String verificationCode = Backend.sendVerificationCode(email);
                        // Prompt for the verification code
                        String inputCode = JOptionPane.showInputDialog(loginFrame,
                                "Enter the verification code sent to your email:", "Verify Email",
                                JOptionPane.PLAIN_MESSAGE);
                        if (inputCode == null) {
                            // User canceled the operation
                            break;
                        }
                        if (verificationCode.equals(inputCode)) {
                            // Alert confirming successful verification
                            JOptionPane.showMessageDialog(loginFrame,
                                    "Code verified successfully.", "Verification Success",
                                    JOptionPane.INFORMATION_MESSAGE);
                            // Prompt to enter new password
                            String newPassword;
                            do {
                                newPassword = JOptionPane.showInputDialog(loginFrame,
                                        "Enter your new password (must be at least 8 characters):",
                                        "Reset Password", JOptionPane.PLAIN_MESSAGE);
                                if (newPassword != null && newPassword.length() < 8) {
                                    // Alert for password length
                                    JOptionPane.showMessageDialog(loginFrame,
                                            "Password must be at least 8 characters long.",
                                            "Password Length Error", JOptionPane.ERROR_MESSAGE);
                                }
                            } while (newPassword != null && newPassword.length() < 8);

                            if (newPassword != null) {
                                // Update the password in the database
                                Backend.updatePassword(email, newPassword);
                                JOptionPane.showMessageDialog(loginFrame,
                                        "Password has been reset successfully. Please login again.", "Password Reset",
                                        JOptionPane.INFORMATION_MESSAGE);
                                // Now show the login frame again
                                loginFrame.setVisible(true);
                                codeVerified = true; // Set flag to true to exit the loop
                            }
                        } else {
                            JOptionPane.showMessageDialog(loginFrame, "Invalid verification code.", "Error",
                                    JOptionPane.ERROR_MESSAGE);
                        }
                    }
                } else {
                    JOptionPane.showMessageDialog(loginFrame, "Email not found.", "Error", JOptionPane.ERROR_MESSAGE);
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

        backButton1.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                fileUploadFrame.setVisible(false);
                userDashboard.showDashboard(); // Show the user dashboard
            }
        });

        // Action listener for email verification button
        emailVerifyButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String emailAddress = regEmailField.getText();
                if (UserAuthentication.isValidEmail(emailAddress)) {
                    int verificationCode = generateVerificationCode();
                    Backend.sendVerificationEmail(emailAddress, verificationCode);
                    enterVerificationCode(verificationCode, regRegisterButton);
                } else {
                    JOptionPane.showMessageDialog(registrationFrame, "Invalid email address.", "Error",
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String filePath = (String) plusSignLabel.getClientProperty("filePath");
                // Get the currently logged-in user's ID
                int userId = UserSession.getInstance().getUserId();

                if (filePath != null && !filePath.isEmpty()) {
                    try {
                        // Check if the file already exists on the server
                        boolean fileExists = Backend.doesFileExist(Paths.get(filePath).getFileName().toString(),
                                userId);

                        if (fileExists) {
                            JOptionPane.showMessageDialog(fileUploadFrame, "File already exists",
                                    "File Exists", JOptionPane.WARNING_MESSAGE);
                            return; // Exit the method without further processing
                        }

                        File selectedFile = new File(filePath);
                        byte[] fileData = Files.readAllBytes(selectedFile.toPath());

                        // Encrypt the file data using AES and DES
                        byte[] combinedEncryptedData = Backend.encryptFileData(fileData);

                        // Upload the file and encrypted data to the server
                        FileManagement.uploadFileToServer(filePath, combinedEncryptedData, userId);

                        // Obtain the fileId somehow
                        int fileId = Backend.obtainFileId(selectedFile.getName(), userId); // Replace obtainFileId()
                                                                                           // with the actual method to
                                                                                           // get fileId

                        // Store the uploaded file in the database
                        Backend.storeUploadedFile(selectedFile.getName(), fileData, fileId);

                        // Show upload success message
                        JOptionPane.showMessageDialog(fileUploadFrame, "File uploaded successfully!",
                                "Upload Successful", JOptionPane.INFORMATION_MESSAGE);

                        // Close the file upload frame
                        fileUploadFrame.dispose();

                        // Show the dashboard
                        userDashboard.createAndShowDashboardGUI(UserSession.getInstance().getUsername());

                    } catch (IOException | GeneralSecurityException ex) {
                        ex.printStackTrace();
                        uploadLabel.setText("Error during encryption or uploading file.");
                    }
                } else {
                    uploadLabel.setText("No file selected.");
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

        // Check for network connection status
        Timer timer = new Timer();
        timer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                checkNetworkConnection();
            }
        }, 0, 1000); // Check every 1 seconds

        // Display the login frame
        loginFrame.setVisible(true);
    }

    private static int generateVerificationCode() {
        Random random = new Random();
        return random.nextInt(90000) + 10000; // Generate a random 5-digit code
    }

    private static void enterVerificationCode(int verificationCode, JButton regRegisterButton) {
        JFrame verificationFrame = new JFrame("Enter Verification Code");
        JTextField verificationTextField = new JTextField(10);
        JButton verifyButton = new JButton("Verify");

        verifyButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String enteredCode = verificationTextField.getText();
                if (enteredCode.equals(String.valueOf(verificationCode))) {
                    JOptionPane.showMessageDialog(verificationFrame, "Email verified successfully!", "Success",
                            JOptionPane.INFORMATION_MESSAGE);
                    emailVerified.set(true);
                    regRegisterButton.setEnabled(true);
                    verificationFrame.dispose();
                } else {
                    JOptionPane.showMessageDialog(verificationFrame, "Invalid verification code. Please try again.",
                            "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        JPanel panel = new JPanel();
        panel.add(new JLabel("Enter Verification Code: "));
        panel.add(verificationTextField);
        panel.add(verifyButton);

        verificationFrame.add(panel);
        verificationFrame.setSize(300, 150);
        verificationFrame.setVisible(true);
    }

    private static void checkNetworkConnection() {
        boolean isConnected = isInternetReachable();
        if (isConnected) {
            internetStatusLabel.setText("Internet status: Connected");
        } else {
            internetStatusLabel.setText("Internet status: Disconnected");
        }
    }

    private static boolean isInternetReachable() {
        try {
            InetAddress address = InetAddress.getByName("www.google.com");
            return address.isReachable(1000); // Timeout set to 1 second
        } catch (IOException e) {
            return false;
        }
    }

}

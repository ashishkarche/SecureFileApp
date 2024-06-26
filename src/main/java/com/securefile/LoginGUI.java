/**
 * The `GUI` class in the `com.securefile` package contains methods to create and display graphical
 * user interfaces for login, registration, dashboard, and file upload functionalities.
 */
package com.securefile;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
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
import java.net.URL;

public class LoginGUI {
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

    // Create a flag to track email verification
    public static AtomicBoolean emailVerified = new AtomicBoolean(false);

    public static ImageIcon createImageIcon(String path) {
        URL imgURL = LoginGUI.class.getResource(path);
        if (imgURL != null) {
            return new ImageIcon(imgURL);
        } else {
            System.err.println("Couldn't find file: " + path);
            return null;
        }
    }

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
        menuBar.add(Box.createHorizontalGlue());
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

        JLabel plusSignLabel = new JLabel(createImageIcon("/plus.png"));
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
                    // Perform admin login authentication with IP address
                    if (Backend.authenticateAdmin(username, password, ipAddress)) {
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
        // Add a WindowListener to clear fields when the frame is closed
        registrationFrame.addWindowListener(new java.awt.event.WindowAdapter() {
            @Override
            public void windowClosing(java.awt.event.WindowEvent windowEvent) {
                clearRegistrationFields();
            }
        });

        // Registration button action listener
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
                String email = regEmailField.getText();
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
                if (UserAuthentication.registerUser(email, username, password, ipAddress)) {
                    JOptionPane.showMessageDialog(registrationFrame, "Registration successful", "Registration",
                            JOptionPane.INFORMATION_MESSAGE);

                    // Make input fields editable again
                    regEmailField.setEditable(true);
                    regUsernameField.setEditable(true);
                    regPasswordField.setEditable(true);

                    // Clear the input fields
                    clearRegistrationFields();

                    registrationFrame.setVisible(false);
                    loginFrame.setVisible(true);
                } else {
                    JOptionPane.showMessageDialog(registrationFrame, "Registration failed", "Registration Error",
                            JOptionPane.ERROR_MESSAGE);

                    // Make input fields editable again in case of failure
                    regEmailField.setEditable(true);
                    regUsernameField.setEditable(true);
                    regPasswordField.setEditable(true);
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
                    JOptionPane.showMessageDialog(loginFrame, "Email is not registered", "Error",
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

                    // Disable input fields
                    regEmailField.setEditable(false);
                    regUsernameField.setEditable(false);
                    regPasswordField.setEditable(false);

                    // Prompt the user to enter the verification code
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
                            // If the file exists for the current user, display a warning message
                            JOptionPane.showMessageDialog(fileUploadFrame, "You have already uploaded this file.",
                                    "File Exists", JOptionPane.WARNING_MESSAGE);
                            return; // Exit the method without further processing
                        }

                        File selectedFile = new File(filePath);
                        byte[] fileData = Files.readAllBytes(selectedFile.toPath());

                        byte[] combinedEncryptedData;
                        String fileExtension = FileManagement.getFileExtension(selectedFile);
                        // Measure encryption time
                        // long encryptionStartTime = System.nanoTime();
                        if (fileExtension != null && (fileExtension.equals("txt") || fileExtension.equals("pdf")
                                || fileExtension.equals("zip") || FileManagement.isImage(fileExtension)
                                || fileExtension.equalsIgnoreCase("exe"))) {
                            // Encrypt text, PDF, zip, image, or exe file using AES
                            combinedEncryptedData = Backend.encryptFileData(fileData);
                        } else {
                            // Unsupported file type
                            JOptionPane.showMessageDialog(fileUploadFrame,
                                    "Unsupported file type. Please select a text file, a PDF file, a zip file, an image file, or an executable file.",
                                    "Unsupported File Type", JOptionPane.ERROR_MESSAGE);
                            return; // Exit the method
                        }
                        // long encryptionEndTime = System.nanoTime();
                        // long encryptionDuration = encryptionEndTime - encryptionStartTime;
                        // Upload the file and encrypted data to the server
                        FileManagement.uploadFileToServer(filePath, combinedEncryptedData, userId);

                        // Obtain the fileId somehow
                        int fileId = Backend.obtainFileId(selectedFile.getName(), userId);

                        // Store the uploaded file in the database
                        FileManagement.storeUploadedFile(selectedFile.getName(), fileData, fileId);

                        // Measure decryption time
                        // long decryptionStartTime = System.nanoTime();
                        // byte[] decryptedData = Backend.decryptFileData(combinedEncryptedData);
                        // long decryptionEndTime = System.nanoTime();
                        // long decryptionDuration = decryptionEndTime - decryptionStartTime;

                        // Log the times to a file
                        // logTimesToFile(selectedFile.getName(), fileData.length, encryptionDuration, decryptionDuration);

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

                // Set the file filter to accept multiple file types
                FileNameExtensionFilter filter = new FileNameExtensionFilter(
                        "Text Files (*.txt), PDF Files (*.pdf), ZIP Files (*.zip), Image Files (*.png, *.jpg, *.gif), Executable Files (*.exe)",
                        "txt", "pdf", "zip", "png", "jpg", "gif", "exe");
                fileChooser.setFileFilter(filter);

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

    // Method to log encryption and decryption times to a file
    // private static void logTimesToFile(String fileName, long fileSize, long encryptionTime, long decryptionTime) {
    //     try (BufferedWriter writer = new BufferedWriter(
    //             new FileWriter("encryption_decryption_times_report.txt", true))) {
    //         writer.write("File Name: " + fileName);
    //         writer.write(", File Size: " + fileSize + " bytes");
    //         writer.write(", Encryption Time: " + encryptionTime + " ns");
    //         writer.write(", Decryption Time: " + decryptionTime + " ns");
    //         writer.newLine();
    //     } catch (IOException e) {
    //         e.printStackTrace();
    //     }
    // }

    // Method to clear registration input fields
    private static void clearRegistrationFields() {
        regEmailField.setText("");
        regUsernameField.setText("");
        regPasswordField.setText("");
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
            // Enable buttons and inputs
            enableComponents(loginFrame, true);
            internetStatusLabel.setText("Internet status: Connected");
        } else {
            // Disable buttons and inputs
            enableComponents(loginFrame, false);
            internetStatusLabel.setText("Internet status: Disconnected");
            // Show alert for network error
            JOptionPane.showMessageDialog(loginFrame, "Network error. You are offline.", "Network Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    // Method to enable or disable all components in a container
    private static void enableComponents(Container container, boolean enable) {
        Component[] components = container.getComponents();
        for (Component component : components) {
            if (component instanceof JPanel) {
                enableComponents((Container) component, enable);
            }
            component.setEnabled(enable);
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

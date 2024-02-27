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
import java.nio.file.Files;
// import java.nio.file.Path;
import java.nio.file.Paths;

import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.AbstractTableModel;

import java.util.ArrayList;
import java.util.List;

import java.security.GeneralSecurityException;

public class GUI {
    private static JFrame loginFrame;
    private static JTextField usernameField;
    private static JPasswordField passwordField;
    private static JFrame registrationFrame;
    private static JTextField regEmailField;
    private static JTextField regUsernameField;
    private static JPasswordField regPasswordField;
    private static JFrame fileUploadFrame;
    private static JLabel uploadLabel;
    private static JLabel passwordLengthLabel;
    private static boolean fileUploadSuccess = false;

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
        regEmailField = new JTextField(20);
        regUsernameField = new JTextField(20);
        regPasswordField = new JPasswordField(20);
        JButton regRegisterButton = new JButton("Register");
        JButton backButton = new JButton("Back to Login");

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

        // Create the file upload frame
        fileUploadFrame = new JFrame("File Upload");
        fileUploadFrame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        fileUploadFrame.setSize(500, 500);
        fileUploadFrame.setLayout(new GridBagLayout());

        JLabel plusSignLabel = new JLabel(new ImageIcon("src/main/resources/plus.png"));
        uploadLabel = new JLabel("Select File");
        uploadLabel.setFont(new Font("Arial", Font.BOLD, 12));
        JButton encryptButton = new JButton("Upload file");
 
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

                if (Backend.authenticateUser(username, password)) {
                    // Login successful, show dashboard
                    createAndShowDashboardGUI(username);
                    loginFrame.setVisible(false);
                } else {
                    JOptionPane.showMessageDialog(loginFrame, "Invalid username or password", "Login Error",
                            JOptionPane.ERROR_MESSAGE);
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
                String email = regEmailField.getText(); // Retrieve email
                String username = regUsernameField.getText();
                char[] passwordChars = regPasswordField.getPassword();
                String password = new String(passwordChars);

                if (password.length() != 8) { // Check password length
                    passwordLengthLabel.setText("Password should be 8 characters long");
                    return;
                } else {
                    passwordLengthLabel.setText(""); // Clear password length message
                }

                if (Backend.registerUser(email, username, password)) { // Register user with email
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
                // Get the currently logged-in user's ID
                int userId = UserSession.getInstance().getUserId();

                if (filePath != null && !filePath.isEmpty()) {
                    try {
                        // Check if the file already exists on the server
                        boolean fileExists = Backend.doesFileExist(Paths.get(filePath).getFileName().toString(),userId);

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
                        Backend.uploadFileToServer(filePath, combinedEncryptedData, userId);

                        // Show upload success message
                        JOptionPane.showMessageDialog(fileUploadFrame, "File uploaded successfully!",
                                "Upload Successful", JOptionPane.INFORMATION_MESSAGE);

                        // Close the file upload frame
                        fileUploadFrame.dispose();

                        // Show the dashboard
                        createAndShowDashboardGUI(UserSession.getInstance().getUsername());

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

        // Display the login frame
        loginFrame.setVisible(true);
    }

    public static void createAndShowDashboardGUI(String username) {
        JFrame dashboardFrame = new JFrame("Dashboard - " + username);
        dashboardFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        dashboardFrame.setSize(800, 600);

        JPanel dashboardPanel = new JPanel(new BorderLayout());
        dashboardFrame.add(dashboardPanel);

        // Add the plus.png icon in the right-hand corner
        ImageIcon plusIcon = new ImageIcon("src/main/resources/plus.png");
        Image smallPlusImage = plusIcon.getImage().getScaledInstance(25, 25, Image.SCALE_SMOOTH);
        ImageIcon smallPlusIcon = new ImageIcon(smallPlusImage);
        JLabel plusLabel = new JLabel(smallPlusIcon);
        plusLabel.setHorizontalAlignment(SwingConstants.RIGHT);
        dashboardPanel.add(plusLabel, BorderLayout.NORTH);

        JTable fileTable = new JTable(new FileTableModel());
        dashboardPanel.add(new JScrollPane(fileTable), BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel();
        dashboardPanel.add(buttonPanel, BorderLayout.SOUTH);

        JButton shareButton = new JButton("Share");
        buttonPanel.add(shareButton);

        JButton downloadButton = new JButton("Download");
        buttonPanel.add(downloadButton);

        JButton deleteButton = new JButton("Delete");
        buttonPanel.add(deleteButton);
        dashboardPanel.add(buttonPanel, BorderLayout.SOUTH);

        // Add logout button in the bottom right corner
        JButton logoutButton = new JButton("Logout");
        buttonPanel.add(logoutButton);
        dashboardPanel.add(buttonPanel, BorderLayout.SOUTH);

        dashboardFrame.setVisible(true);

        downloadButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int selectedRow = fileTable.getSelectedRow();
                if (selectedRow != -1) {
                    String fileName = (String) fileTable.getValueAt(selectedRow, 1);

                    // Download the encrypted file from the server
                    byte[] encryptedData = Backend.downloadEncryptedFileFromServer(fileName);

                    if (encryptedData != null) {
                        try {
                            // Decrypt the encrypted data
                            byte[] decryptedData = Backend.decryptFileData(encryptedData);

                            // Choose a location to save the decrypted file
                            JFileChooser fileChooser = new JFileChooser();
                            fileChooser.setDialogTitle("Save File");
                            int userSelection = fileChooser.showSaveDialog(null);

                            if (userSelection == JFileChooser.APPROVE_OPTION) {
                                File decryptedFile = fileChooser.getSelectedFile();

                                // Write the decrypted data to the selected file
                                Files.write(decryptedFile.toPath(), decryptedData);

                                JOptionPane.showMessageDialog(dashboardFrame,
                                        "File Saved: " + decryptedFile.getAbsolutePath(),
                                        "Download Successful", JOptionPane.INFORMATION_MESSAGE);
                            } else {
                                JOptionPane.showMessageDialog(dashboardFrame, "Download canceled or file not saved.",
                                        "Download Canceled", JOptionPane.WARNING_MESSAGE);
                            }
                        } catch (GeneralSecurityException | IOException ex) {
                            ex.printStackTrace();
                            JOptionPane.showMessageDialog(dashboardFrame,
                                    "Error during decryption or file saving.", "Error", JOptionPane.ERROR_MESSAGE);
                        }
                    } else {
                        JOptionPane.showMessageDialog(dashboardFrame, "Error: Unable to download the encrypted file.",
                                "Download Error", JOptionPane.ERROR_MESSAGE);
                    }
                } else {
                    JOptionPane.showMessageDialog(dashboardFrame, "Please select a file to download.",
                            "No File Selected",
                            JOptionPane.WARNING_MESSAGE);
                }
            }
        });

        plusLabel.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                fileUploadFrame.setVisible(true);
                dashboardFrame.setVisible(false);
            }
        });
        
        // The window listener to the `fileUploadFrame` in Java Swing. When the
        // window is closing, it will make the `dashboardFrame` visible.
        fileUploadFrame.addWindowListener(new java.awt.event.WindowAdapter() {
            @Override
            public void windowClosing(java.awt.event.WindowEvent evt){
                dashboardFrame.setVisible(true);
            }
        });

        logoutButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // Logout the user
                UserSession.getInstance().logoutUser();

                clearLoginFields();

                // Close file upload frame
                dashboardFrame.dispose();

                // Show login frame
                loginFrame.setVisible(true);
            }
        });

        deleteButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int selectedRow = fileTable.getSelectedRow();
                if (selectedRow != -1) {
                    int fileId = (int) fileTable.getValueAt(selectedRow, 0);
                    String fileName = (String) fileTable.getValueAt(selectedRow, 1);
                    boolean deleted = Backend.deleteFileFromServer(fileId, fileName);
                    if (deleted) {
                        // Refresh the table
                        ((FileTableModel) fileTable.getModel()).refreshData();
                        JOptionPane.showMessageDialog(dashboardFrame, "File deleted successfully.");
                    } else {
                        JOptionPane.showMessageDialog(dashboardFrame, "Error deleting file.", "Error",
                                JOptionPane.ERROR_MESSAGE);
                    }
                } else {
                    JOptionPane.showMessageDialog(dashboardFrame, "Please select a file to delete.", "Warning",
                            JOptionPane.WARNING_MESSAGE);
                }
            }
        });

    }

    private static class FileTableModel extends AbstractTableModel {
        private String[] columnNames = { "File No.", "File Name" };
        private List<Object[]> data;
        // Get the current user ID from the session
        int userId = UserSession.getInstance().getUserId();

        public FileTableModel() {
            this.data = fetchData();
        }

        private List<Object[]> fetchData() {
            Object[][] fetchedData = Backend.fetchFileData(userId);
            List<Object[]> dataList = new ArrayList<>();
            for (Object[] row : fetchedData) {
                dataList.add(row);
            }
            return dataList;
        }

        public void refreshData() {
            this.data = fetchData();
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() {
            return data.size();
        }

        @Override
        public int getColumnCount() {
            return columnNames.length;
        }

        @Override
        public String getColumnName(int column) {
            return columnNames[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            return data.get(rowIndex)[columnIndex];
        }
    }

    private static void clearLoginFields() {
        usernameField.setText("");
        passwordField.setText("");
    }

}

package com.securefile;

import java.io.File;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;

import FileManager.FileManagement;
import MailserverManager.EmailConfigLoader;
import UserManager.UserSession;

import java.awt.*;
import java.awt.event.*;

public class userDashboard {

    public static String ImagePath = "/plus.png"; // Replace Image Path with your Image path

    public static void createAndShowDashboardGUI(String username) {
        JFrame dashboardFrame = new JFrame("Dashboard - " + username);
        dashboardFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        dashboardFrame.setSize(800, 600);

        JPanel dashboardPanel = new JPanel(new BorderLayout());
        dashboardFrame.add(dashboardPanel);

        // Load the image as a resource
        ImageIcon plusIcon = new ImageIcon(userDashboard.class.getResource(ImagePath));
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

                // Check network connection before proceeding
                if (!isInternetReachable()) {
                    // Disable buttons and show alert for network error
                    disableButtonsAndShowAlert(dashboardFrame);
                    return;
                }

                int selectedRow = fileTable.getSelectedRow();
                if (selectedRow != -1) {
                    int fileId = (int) fileTable.getValueAt(selectedRow, 0);
                    // Get the user ID from the session
                    int userId = UserSession.getInstance().getUserId();

                    // Download the encrypted file from the server
                    byte[] encryptedData = FileManagement.downloadEncryptedFileFromServer(fileId, userId);

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

        shareButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                // Check network connection before proceeding
                if (!isInternetReachable()) {
                    // Disable buttons and show alert for network error
                    disableButtonsAndShowAlert(dashboardFrame);
                    return;
                }

                // Get the selected row in the table
                int selectedRow = fileTable.getSelectedRow();
                if (selectedRow != -1) {

                    int fileId = (int) fileTable.getValueAt(selectedRow, 0);
                    // Retrieve the file name from the selected row
                    String fileName = (String) fileTable.getValueAt(selectedRow, 1);

                    // Get the current user's ID
                    int userId = UserSession.getInstance().getUserId();

                    // Set the expiry time for the download link (in minutes)
                    String linkExpiryTime = "60"; // Change this as needed

                    // Prompt the user to enter the receiver's email address
                    String receiverEmail = JOptionPane.showInputDialog(dashboardFrame, "Enter receiver's email:");

                    if (receiverEmail != null && !receiverEmail.isEmpty()) {
                        // Generate the download link for the file
                        String downloadLink = Backend.generateDownloadLink(fileName, fileId, userId, linkExpiryTime);

                        // Send an email to the receiver with the download link
                        Backend.sendEmail(receiverEmail, EmailConfigLoader.getSmtpUsername(), downloadLink);

                        // Show a confirmation message to the user
                        JOptionPane.showMessageDialog(dashboardFrame, "Email sent to " + receiverEmail,
                                "Email Sent", JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        // If the user cancels or leaves the email field empty
                        JOptionPane.showMessageDialog(dashboardFrame, "Receiver's email is required",
                                "Email Required", JOptionPane.WARNING_MESSAGE);
                    }
                } else {
                    // If no file is selected
                    JOptionPane.showMessageDialog(dashboardFrame, "Please select a file to share.",
                            "No File Selected", JOptionPane.WARNING_MESSAGE);
                }
            }
        });

        plusLabel.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                LoginGUI.fileUploadFrame.setVisible(true);
                dashboardFrame.setVisible(false);
            }
        });

        // The window listener to the `fileUploadFrame` in Java Swing. When the
        // window is closing, it will make the `dashboardFrame` visible.
        LoginGUI.fileUploadFrame.addWindowListener(new java.awt.event.WindowAdapter() {
            @Override
            public void windowClosing(java.awt.event.WindowEvent evt) {
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
                LoginGUI.loginFrame.setVisible(true);
            }
        });

        deleteButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int selectedRow = fileTable.getSelectedRow();
                if (selectedRow != -1) {
                    int fileId = (int) fileTable.getValueAt(selectedRow, 0);
                    String fileName = (String) fileTable.getValueAt(selectedRow, 1);
                    boolean deleted = FileManagement.deleteFileFromServer(fileId, fileName);
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

    // Method to disable buttons and show alert for network error
    private static void disableButtonsAndShowAlert(JFrame dashboardFrame) {
        // Disable buttons
        Component[] components = dashboardFrame.getRootPane().getContentPane().getComponents();
        for (Component component : components) {
            if (component instanceof JButton) {
                ((JButton) component).setEnabled(false);
            }
        }
        // Show alert for network error
        JOptionPane.showMessageDialog(dashboardFrame, "Network error. You are offline.", "Network Error",
                JOptionPane.ERROR_MESSAGE);
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

    // Method to check internet connectivity
    private static boolean isInternetReachable() {
        try {
            // Make a HTTP request to a known reliable server
            HttpURLConnection urlConn = (HttpURLConnection) (new URL("http://www.google.com").openConnection());
            urlConn.setRequestProperty("User-Agent", "Test");
            urlConn.setRequestProperty("Connection", "close");
            urlConn.setConnectTimeout(5000);
            urlConn.connect();
            return (urlConn.getResponseCode() == 200);
        } catch (IOException e) {
            return false;
        }
    }

    public static void clearLoginFields() {
        LoginGUI.usernameField.setText("");
        LoginGUI.passwordField.setText("");
    }

    public static void showDashboard() {
        String username = UserSession.getInstance().getUsername();
        createAndShowDashboardGUI(username);
    }
}

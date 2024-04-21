package com.securefile;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

import javax.swing.*;
import DatabaseManager.DatabaseConfig;

public class Main {
    public static void main(String[] args) {
        Loader.showLoader(); // Show the loader
        SwingUtilities.invokeLater(() -> {
            boolean connected = attemptConnection(); // Attempt to connect to the server
            if (connected) {
                LoginGUI.createAndShowLoginGUI(); // Create and show login GUI if connected successfully
            } else {
                // Display alert message if unable to connect to the server
                JOptionPane.showMessageDialog(null, "Can't connect to the server. Please try again later.",
                        "Connection Error", JOptionPane.ERROR_MESSAGE);
            }
            Loader.hideLoader(); // Hide the loader
        });
    }

    private static boolean attemptConnection() {
        // Attempt to connect to the database using DatabaseConfig
        try {
            // Get database connection properties from DatabaseConfig
            String url = DatabaseConfig.getUrl();
            String user = DatabaseConfig.getUser();
            String password = DatabaseConfig.getPassword();

            // Attempt to establish a connection to the database
            Connection connection = DriverManager.getConnection(url, user, password);

            // If connection is successful, return true
            if (connection != null) {
                connection.close(); // Close the connection
                return true;
            } else {
                return false;
            }
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }
}

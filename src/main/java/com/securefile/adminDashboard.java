package com.securefile;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import UserManager.UserSession;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;

import UserManager.UserQueries;


public class adminDashboard {

    public static void createAndShowAdminDashboardGUI() {
        JFrame adminDashboardFrame = new JFrame("Admin Dashboard");
        adminDashboardFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        adminDashboardFrame.setSize(800, 600);

        JPanel adminDashboardPanel = new JPanel(new BorderLayout());
        adminDashboardFrame.add(adminDashboardPanel);

        // Fetch users data from the database initially
        Object[][] userData = UserQueries.fetchAllUsersData();
        String[] columnNames = { "User ID", "Username", "Email" };

        JTable userTable = new JTable(userData, columnNames);
        JScrollPane scrollPane = new JScrollPane(userTable);
        adminDashboardPanel.add(scrollPane, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton deleteUserButton = new JButton("Delete User");
        buttonPanel.add(deleteUserButton);
        adminDashboardPanel.add(buttonPanel, BorderLayout.SOUTH);

        // Add logout button in the bottom right corner
        JButton logoutButton = new JButton("Logout");
        buttonPanel.add(logoutButton);
        adminDashboardPanel.add(buttonPanel, BorderLayout.SOUTH);

        deleteUserButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int selectedRow = userTable.getSelectedRow();
                if (selectedRow != -1) {
                    int userId = (int) userTable.getValueAt(selectedRow, 0);
                    deleteUser(adminDashboardFrame, userId, userTable, selectedRow);
                } else {
                    JOptionPane.showMessageDialog(adminDashboardFrame, "Please select a user to delete.",
                            "Warning", JOptionPane.WARNING_MESSAGE);
                }
            }
        });

        logoutButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // Logout the user
                UserSession.getInstance().logoutUser();

                userDashboard.clearLoginFields();

                // Close file upload frame
                adminDashboardFrame.dispose();

                // Show login frame
                GUI.loginFrame.setVisible(true);
            }
        });

        adminDashboardFrame.setVisible(true);
    }

    private static void deleteUser(JFrame adminDashboardFrame, int userId, JTable userTable, int selectedRow) {
        boolean deleted = UserQueries.deleteUser(userId);
        if (deleted) {
            JOptionPane.showMessageDialog(adminDashboardFrame, "User deleted successfully.");
            // Refresh the table
            TableModel model = userTable.getModel();
            if (model instanceof DefaultTableModel) {
                DefaultTableModel defaultModel = (DefaultTableModel) model;
                defaultModel.setRowCount(0); // Clear existing data
                Object[][] userData = UserQueries.fetchAllUsersData();
                for (Object[] row : userData) {
                    defaultModel.addRow(row);
                }
            }
        } else {
            JOptionPane.showMessageDialog(adminDashboardFrame, "Error deleting user.", "Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }
}

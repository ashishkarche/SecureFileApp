package UserManager;

import java.sql.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import DatabaseManager.DatabaseConfig;


public class UserAuthentication {
    private static final String DB_URL = DatabaseConfig.getUrl();
    private static final String DB_USER = DatabaseConfig.getUser();
    private static final String DB_PASSWORD = DatabaseConfig.getPassword(); 
    private static final String USER_TABLE = "users";
    private static UserSession userSession = UserSession.getInstance();


    public static boolean registerUser(String email, String username, String password, String ipAddress) {
        if (!isValidEmail(email) || isEmailRegistered(email) || isUsernameTaken(username)) {
            return false;
        }
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                PreparedStatement statement = connection.prepareStatement(
                        "INSERT INTO " + USER_TABLE + " (email, username, password, ip_address) VALUES (?, ?, ?, ?)")) {
            statement.setString(1, email); // Add email to registration query
            statement.setString(2, username);
            statement.setString(3, hashPassword(password)); // Hashing the password
            statement.setString(4, ipAddress); // Store IP address
            int rowsAffected = statement.executeUpdate();
            return rowsAffected > 0; // If at least one row is affected, registration succeeds
        } catch (SQLException | NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            return false;
        }
    }

        // Method to validate email address format
    public static boolean isValidEmail(String email) {
        String emailRegex = "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$";
        Pattern pattern = Pattern.compile(emailRegex);
        Matcher matcher = pattern.matcher(email);
        return matcher.matches();
    }

    // Check if the email is already registered
    public static boolean isEmailRegistered(String email) {
        return isFieldExists("email", email, USER_TABLE);
    }

    // Check if the username is already taken
    public static boolean isUsernameTaken(String username) {
        return isFieldExists("username", username, USER_TABLE);
    }

    // Check if a field value exists in a table
    public static boolean isFieldExists(String fieldName, String value, String tableName) {
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                PreparedStatement statement = connection
                        .prepareStatement(
                                "SELECT COUNT(*) AS count FROM " + tableName + " WHERE " + fieldName + " = ?")) {
            statement.setString(1, value);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    int count = resultSet.getInt("count");
                    return count > 0;
                }
            }
        } catch (SQLException ex) {
            ex.printStackTrace();
        }
        return false;
    }

    private static String hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashedBytes = md.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(hashedBytes);
    }
    // User login authentication code with IP address verification
    public static boolean authenticateUser(String username, String password, String ipAddress) {
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                PreparedStatement statement = connection.prepareStatement(
                        "SELECT id, username, email, password, ip_address FROM " + USER_TABLE
                                + " WHERE username = ?")) {
            statement.setString(1, username);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    int userId = resultSet.getInt("id");
                    String userEmail = resultSet.getString("email"); // Retrieve user's email
                    String hashedPassword = resultSet.getString("password");
                    String savedIpAddress = resultSet.getString("ip_address");
                    // Verify username, password, and IP address
                    if (verifyPassword(password, hashedPassword) && ipAddress.equals(savedIpAddress)) {
                        // Store user's email in the session
                        userSession.loginUser(userId, username, userEmail);
                        return true;
                    }
                }
            }
        } catch (SQLException | NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        }
        return false;
    }
    private static boolean verifyPassword(String password, String hashedPassword) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashedBytes = md.digest(password.getBytes());
        String hashedInputPassword = Base64.getEncoder().encodeToString(hashedBytes);
        return hashedInputPassword.equals(hashedPassword);
    }

    // Other authentication and registration helper methods...
}

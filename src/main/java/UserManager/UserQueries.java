package UserManager;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

import DatabaseManager.DatabaseConfig;

public class UserQueries {
    private static final String DB_URL = DatabaseConfig.getUrl();
    private static final String DB_USER = DatabaseConfig.getUser();
    private static final String DB_PASSWORD = DatabaseConfig.getPassword();

    private static final String USER_TABLE = "users";
    private static final String ENCRYPTED_FILES_TABLE = "encrypted_files";

    public static Object[][] fetchAllUsersData() {
        List<Object[]> userList = new ArrayList<>();

        String query = "SELECT u.id, u.username, u.email, ef.file_name " +
                       "FROM " + USER_TABLE + " u " +
                       "LEFT JOIN " + ENCRYPTED_FILES_TABLE + " ef ON u.id = ef.user_id";

        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement statement = connection.prepareStatement(query);
             ResultSet resultSet = statement.executeQuery()) {

            while (resultSet.next()) {
                int id = resultSet.getInt("id");
                String username = resultSet.getString("username");
                String email = resultSet.getString("email");
                String fileName = resultSet.getString("file_name");
                userList.add(new Object[] { id, username, email, fileName });
            }

        } catch (SQLException ex) {
            ex.printStackTrace();
        }

        // Convert the list of users to a two-dimensional array
        return userList.toArray(new Object[0][0]);
    }

    public static boolean deleteUser(int userId) {
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            // Delete associated rows in the encrypted_files table
            String deleteFilesSql = "DELETE FROM " + ENCRYPTED_FILES_TABLE + " WHERE user_id = ?";
            try (PreparedStatement deleteFilesStatement = connection.prepareStatement(deleteFilesSql)) {
                deleteFilesStatement.setInt(1, userId);
                deleteFilesStatement.executeUpdate();
            }

            // Now delete the user
            String deleteUserSql = "DELETE FROM " + USER_TABLE + " WHERE id = ?";
            try (PreparedStatement deleteUserStatement = connection.prepareStatement(deleteUserSql)) {
                deleteUserStatement.setInt(1, userId);
                int rowsAffected = deleteUserStatement.executeUpdate();
                return rowsAffected > 0;
            }
        } catch (SQLException ex) {
            ex.printStackTrace();
            return false;
        }
    }
}

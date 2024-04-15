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
        List<User> userList = new ArrayList<>();

        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                PreparedStatement statement = connection
                        .prepareStatement("SELECT id, username, email FROM " + USER_TABLE);
                ResultSet resultSet = statement.executeQuery()) {

            while (resultSet.next()) {
                int id = resultSet.getInt("id");
                String username = resultSet.getString("username");
                String email = resultSet.getString("email");
                userList.add(new User(id, username, email));
            }

        } catch (SQLException ex) {
            ex.printStackTrace();
        }

        // Convert the list of users to a two-dimensional array
        Object[][] userData = new Object[userList.size()][3];
        for (int i = 0; i < userList.size(); i++) {
            User user = userList.get(i);
            userData[i][0] = user.getId();
            userData[i][1] = user.getUsername();
            userData[i][2] = user.getEmail();
        }

        return userData;
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

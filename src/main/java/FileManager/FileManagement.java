package FileManager;

import java.sql.*;

import DatabaseManager.DatabaseConfig;

import java.nio.file.Paths;

public class FileManagement {
    private static final String DB_URL = DatabaseConfig.getUrl();
    private static final String DB_USER = DatabaseConfig.getUser();
    private static final String DB_PASSWORD = DatabaseConfig.getPassword();
    private static final String ENCRYPTED_FILES_TABLE = "encrypted_files";
    private static final String UPLOADED_FILES_TABLE = "uploaded_files";

    public static void uploadFileToServer(String filePath, byte[] encryptedData, int userId) {
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String insertSql = "INSERT INTO " + ENCRYPTED_FILES_TABLE
                    + " (file_name, encrypted_data, user_id) VALUES (?, ?, ?)";
            try (PreparedStatement insertStatement = connection.prepareStatement(insertSql)) {
                insertStatement.setString(1, Paths.get(filePath).getFileName().toString());
                insertStatement.setBytes(2, encryptedData);
                insertStatement.setInt(3, userId); // Include user ID
                insertStatement.executeUpdate();
            }
        } catch (SQLException ex) {
            ex.printStackTrace();
        }
    }

    public static byte[] downloadEncryptedFileFromServer(int fileId, int userId) {
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                PreparedStatement statement = connection.prepareStatement(
                        "SELECT encrypted_data FROM " + ENCRYPTED_FILES_TABLE + " WHERE file_id = ? AND user_id = ?")) {
            statement.setInt(1, fileId);
            statement.setInt(2, userId);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    return resultSet.getBytes("encrypted_data");
                }
            }
        } catch (SQLException ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public static boolean deleteFileFromServer(int fileId, String fileName) {
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String deleteSql = "DELETE FROM " + ENCRYPTED_FILES_TABLE + " WHERE file_id = ?";
            try (PreparedStatement deleteStatement = connection.prepareStatement(deleteSql)) {
                deleteStatement.setInt(1, fileId);
                int rowsAffected = deleteStatement.executeUpdate();
                return rowsAffected > 0;
            }
        } catch (SQLException ex) {
            ex.printStackTrace();
            return false;
        }
    }

        // Store uploaded file in the database
        public static void storeUploadedFile(String fileName, byte[] fileData, int fileId) {
            try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                    PreparedStatement statement = connection
                            .prepareStatement(
                                    "INSERT INTO `" + UPLOADED_FILES_TABLE
                                            + "` (file_id,file_name, file_data) VALUES (?, ?, ?)")) {
                statement.setInt(1, fileId);
                statement.setString(2, fileName);
                statement.setBytes(3, fileData);
                statement.executeUpdate();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
}

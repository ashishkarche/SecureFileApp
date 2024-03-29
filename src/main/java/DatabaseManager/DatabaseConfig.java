package DatabaseManager;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public class DatabaseConfig {
    private static final String PROPERTIES_FILE = "src/main/resources/Properties/database.properties";
    // Properties object to hold the configuration values
    private static final Properties props = new Properties();
    
    static {
        try (FileInputStream input = new FileInputStream(PROPERTIES_FILE)) {
            // Loading properties from file
            props.load(input);
        } catch (IOException ex) {
            System.out.println("Failed to load the configuration file.");
            System.out.println("Exception: " + ex.getMessage());
            ex.printStackTrace();
        }
    }
    
    // Methods to retrieve property values
    public static String getUrl() {
        return props.getProperty("db.url");
    }

    public static String getUser() {
        return props.getProperty("db.user");
    }

    public static String getPassword() {
        return props.getProperty("db.password");
    }
}

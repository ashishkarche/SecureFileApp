package DatabaseManager;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class DatabaseConfig {
    private static final String PROPERTIES_FILE = "/Properties/database.properties";
    private static final Properties props = new Properties();
    
    static {
        InputStream input = null;
        try {
            input = DatabaseConfig.class.getResourceAsStream(PROPERTIES_FILE);
            if (input == null) {
                System.out.println("Unable to find " + PROPERTIES_FILE);
            } else {
                // Loading properties from file
                props.load(input);
            }
        } catch (IOException ex) {
            System.out.println("Failed to load the configuration file.");
            System.out.println("Exception: " + ex.getMessage());
            ex.printStackTrace();
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException e) {
                    System.out.println("Failed to close the input stream.");
                    System.out.println("Exception: " + e.getMessage());
                    e.printStackTrace();
                }
            }
        }
    }
    
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

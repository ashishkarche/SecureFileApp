package MailserverManager;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class EmailConfigLoader {
    private static final String PROPERTIES_FILE = "/Properties/email.properties";
    private static final Properties emailProps = new Properties();

    static {
        InputStream input = null;
        try {
            input = EmailConfigLoader.class.getResourceAsStream(PROPERTIES_FILE);
            if (input == null) {
                System.out.println("Unable to find " + PROPERTIES_FILE);
            } else {
                emailProps.load(input);
            }
        } catch (IOException ex) {
            System.out.println("Failed to load the email configuration file.");
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

    // Methods to retrieve email property values
    public static String getSmtpHost() {
        return emailProps.getProperty("mail.smtp.host");
    }

    public static String getSmtpPort() {
        return emailProps.getProperty("mail.smtp.port");
    }

    public static String getSmtpAuth() {
        return emailProps.getProperty("mail.smtp.auth");
    }

    public static String getSmtpStartTls() {
        return emailProps.getProperty("mail.smtp.starttls.enable");
    }

    public static String getSmtpUsername() {
        return emailProps.getProperty("mail.smtp.username");
    }

    public static String getSmtpApiKey() {
        return emailProps.getProperty("mail.smtp.apikey");
    }
}

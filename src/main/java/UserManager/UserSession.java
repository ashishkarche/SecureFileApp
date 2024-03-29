/**
 * The `UserSession` class manages user login sessions by storing user information and providing
 * methods to login, logout, and check login status.
 */
package UserManager;

public class UserSession {
    private static UserSession instance;

    private boolean isLoggedIn;
    private int userId;
    private String username;
    private String email;

    private UserSession() {
        isLoggedIn = false;
    }

    public static UserSession getInstance() {
        if (instance == null) {
            instance = new UserSession();
        }
        return instance;
    }

    public void loginUser(int userId, String username, String email) {
        isLoggedIn = true;
        this.userId = userId;
        this.username = username;
        this.email = email;
    }

    public void setUserId(int userId) {
        this.userId = userId;
    }

    public void logoutUser() {
        isLoggedIn = false;
        userId = 0;
        username = null;
        email = null;
    }

    public boolean isLoggedIn() {
        return isLoggedIn;
    }

    public int getUserId() {
        return userId;
    }

    public String getUsername() {
        return username;
    }

    public String getEmail() {
        return email;
    }
}

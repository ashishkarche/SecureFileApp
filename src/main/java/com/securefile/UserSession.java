package com.securefile;

public class UserSession {
    private static UserSession instance;
    
    private boolean isLoggedIn;
    private int userId;
    private String username;

    private UserSession() {
        isLoggedIn = false;
    }

    public static UserSession getInstance() {
        if (instance == null) {
            instance = new UserSession();
        }
        return instance;
    }

    public void loginUser(int userId, String username) {
        isLoggedIn = true;
        this.userId = userId;
        this.username = username;
    }

    public void logoutUser() {
        isLoggedIn = false;
        userId = 0;
        username = null;
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
}

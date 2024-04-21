package com.securefile;

import javax.swing.*;

public class Loader {
    private static JFrame loaderFrame;
    private static JLabel loadingLabel;

    public static void showLoader() {
        SwingUtilities.invokeLater(() -> {
            loaderFrame = new JFrame("Connecting to server");
            loaderFrame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
            loaderFrame.setSize(400, 120);
            loaderFrame.setLocationRelativeTo(null); // Center the loader frame
            
            // Create a loading label with an animated text
            loadingLabel = new JLabel("Connected to server");
            loaderFrame.add(loadingLabel);
            loaderFrame.setVisible(true);
            
            // Close the loader frame after 15 seconds
            new java.util.Timer().schedule( 
                new java.util.TimerTask() {
                    @Override
                    public void run() {
                        hideLoader();
                    }
                }, 
                15000 
            );
        });
    }

    public static void hideLoader() {
        if (loaderFrame != null) {
            SwingUtilities.invokeLater(() -> {
                loaderFrame.dispose();
            });
        }
    }
}

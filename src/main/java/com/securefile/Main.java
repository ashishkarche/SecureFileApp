/**
 * The Main class in the com.securefile package creates and shows a login GUI using Swing.
 */
package com.securefile;

import javax.swing.*;

public class Main {
    public static void main(String[] args) {
        SwingUtilities.invokeLater(GUI::createAndShowLoginGUI);
    }
}
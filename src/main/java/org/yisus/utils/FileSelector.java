package org.yisus.utils;

import javax.swing.*;
import java.awt.*;
import java.io.File;

public class FileSelector {
    private final JFileChooser fileChooser;

    public FileSelector() {
        fileChooser = new JFileChooser();
    }

    public File selectFile(Component parent) {
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        return openDialog(parent);
    }

    public File selectDirectory(Component parent) {
        fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        return openDialog(parent);
    }

    private File openDialog(Component parent) {
        int code = fileChooser.showOpenDialog(parent);
        if (code == JFileChooser.APPROVE_OPTION) {
            return fileChooser.getSelectedFile();
        }
        return null;
    }
}

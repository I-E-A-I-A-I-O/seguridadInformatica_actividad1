package org.yisus.ui;

import org.yisus.utils.Encryption;
import org.yisus.utils.FileSelector;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

public class MainWindow {
    private JTabbedPane tabPane;
    private JPanel basePanel;
    private JPanel encryptPanel;
    private JPanel decryptPanel;
    private JTextField fileToEncryptTextField;
    private JTextField outputDirectoryTextField;
    private JButton setFileToEncrypt;
    private JButton setOutputDirectory;
    private JButton encryptButton;
    private JProgressBar progressBar;
    private File toEncrypt;
    private File toEncryptDir;
    private File toDecrypt;
    private File toDecryptDir;
    private File toDecryptDigitalSignature;

    public MainWindow() {
        JFrame frame = new JFrame("File encryption and decryption");
        frame.setSize(500, 500);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        final FileSelector fileSelector = new FileSelector();
        final Encryption encryption = new Encryption();

        setFileToEncrypt.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                toEncrypt = fileSelector.selectFile(basePanel);
                if (toEncrypt != null) {
                    fileToEncryptTextField.setText(toEncrypt.getAbsolutePath());
                }
            }
        });
        setOutputDirectory.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                toEncryptDir = fileSelector.selectDirectory(basePanel);
                if (toEncryptDir != null) {
                    outputDirectoryTextField.setText(toEncryptDir.getAbsolutePath());
                }
            }
        });
        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                progressBar.setVisible(true);
                encryptButton.setEnabled(false);
                boolean result = encryption.encrypt(toEncrypt, toEncryptDir);
                if (!result) {
                    JOptionPane.showConfirmDialog(basePanel, "Error encrypting the file.", "Error", JOptionPane.DEFAULT_OPTION, JOptionPane.ERROR_MESSAGE);
                }
                progressBar.setVisible(false);
                encryptButton.setEnabled(true);
            }
        });

        frame.add(basePanel);
        frame.setVisible(true);
    }
}

package org.yisus.ui;

import org.yisus.utils.Encryption;
import org.yisus.utils.FileSelector;

import javax.swing.*;
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
    private JTextField fileToDecryptTextField;
    private JTextField IVFileTextField;
    private JTextField digitalSignatureTextField;
    private JButton setFileToDecryptButton;
    private JButton setIVFileButton;
    private JButton setSignatureButton;
    private JButton decryptButton;
    private JProgressBar decryptProgressBar;
    private JTextField decryptedFileOutputDirectoryTextField;
    private JButton setDecryptionOutputDirButton;
    private File toEncrypt;
    private File toEncryptDir;
    private File toDecrypt;
    private File toDecryptDir;
    private File toDecryptDigitalSignature;
    private File toDecryptIVFile;

    public MainWindow() {
        JFrame frame = new JFrame("File encryption and decryption");
        frame.setSize(500, 500);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        final FileSelector fileSelector = new FileSelector();
        final Encryption encryption = new Encryption();

        setFileToEncrypt.addActionListener(actionEvent -> {
            toEncrypt = fileSelector.selectFile(basePanel);
            if (toEncrypt != null) {
                fileToEncryptTextField.setText(toEncrypt.getAbsolutePath());
            }
        });
        setOutputDirectory.addActionListener(actionEvent -> {
            toEncryptDir = fileSelector.selectDirectory(basePanel);
            if (toEncryptDir != null) {
                outputDirectoryTextField.setText(toEncryptDir.getAbsolutePath());
            }
        });
        encryptButton.addActionListener(actionEvent -> {
            progressBar.setVisible(true);
            encryptButton.setEnabled(false);
            boolean result = encryption.encrypt(toEncrypt, toEncryptDir);
            if (!result) {
                JOptionPane.showConfirmDialog(basePanel, "Error encrypting the file.", "Error", JOptionPane.DEFAULT_OPTION, JOptionPane.ERROR_MESSAGE);
            }
            progressBar.setVisible(false);
            encryptButton.setEnabled(true);
        });
        setFileToDecryptButton.addActionListener(actionEvent -> {
            toDecrypt = fileSelector.selectFile(basePanel);
            if (toDecrypt != null) {
                fileToDecryptTextField.setText(toDecrypt.getAbsolutePath());
            }
        });
        setIVFileButton.addActionListener(actionEvent -> {
            toDecryptIVFile = fileSelector.selectFile(basePanel);
            if (toDecryptIVFile != null) {
                IVFileTextField.setText(toDecryptIVFile.getAbsolutePath());
            }
        });
        setSignatureButton.addActionListener(actionEvent -> {
            toDecryptDigitalSignature = fileSelector.selectFile(basePanel);
            if (toDecryptDigitalSignature != null) {
                digitalSignatureTextField.setText(toDecryptDigitalSignature.getAbsolutePath());
            }
        });
        setDecryptionOutputDirButton.addActionListener(actionEvent -> {
            toDecryptDir = fileSelector.selectDirectory(basePanel);
            if (toDecryptDir != null) {
                decryptedFileOutputDirectoryTextField.setText(toDecryptDir.getAbsolutePath());
            }
        });
        decryptButton.addActionListener(actionEvent -> {
            decryptProgressBar.setVisible(true);
            decryptButton.setEnabled(false);
            encryption.decrypt(toDecrypt, toDecryptDir, toDecryptDigitalSignature, toDecryptIVFile, basePanel);
            decryptProgressBar.setVisible(false);
            decryptButton.setEnabled(true);
        });

        frame.add(basePanel);
        frame.setVisible(true);
    }
}

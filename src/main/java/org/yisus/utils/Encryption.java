package org.yisus.utils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.Properties;

public class Encryption {
    private Properties properties;
    public Encryption() {
        try(InputStream inputStream = Encryption.class.getClassLoader().getResourceAsStream("config.properties")) {
            properties = new Properties();
            properties.load(inputStream);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public boolean encrypt(File toEncrypt, File outputDir) {
        try {
            if (toEncrypt == null || outputDir == null) {
                return false;
            }
            InputStream aesInputStream = Encryption.class.getClassLoader().getResourceAsStream("keystore.jceks");
            KeyStore aesKeyStore = KeyStore.getInstance("PKCS12");
            aesKeyStore.load(aesInputStream, properties.getProperty("encryption.aes.store.pass").toCharArray());
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] iv = new byte[128/8];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(iv);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            cipher.init(
                    Cipher.ENCRYPT_MODE,
                    aesKeyStore.getKey(
                            properties.getProperty("encryption.aes.store.alias"),
                            properties.getProperty("encryption.aes.store.pass").toCharArray()),
                    ivParameterSpec);
            String fileName = toEncrypt.getName().split("\\.")[0] + "_iv.txt";
            File ivFile = new File(outputDir.getAbsolutePath() + "/" + fileName);
            ivFile.createNewFile();
            FileOutputStream ivOutputStream = new FileOutputStream(ivFile);
            ivOutputStream.write(iv);
            ivOutputStream.close();
            FileInputStream toEncryptIS = new FileInputStream(toEncrypt);
            byte[] encrypted = cipher.doFinal(toEncryptIS.readAllBytes());
            String base64Encoded = Base64.getEncoder().encodeToString(encrypted);
            fileName = toEncrypt.getName() + ".enc";
            File encryptedData = new File(outputDir.getAbsolutePath() + "/" + fileName);
            encryptedData.createNewFile();
            FileOutputStream fileOutputStream = new FileOutputStream(encryptedData);
            fileOutputStream.write(base64Encoded.getBytes());
            fileOutputStream.close();
            generateDigitalSignature(toEncrypt, outputDir);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
    private void generateDigitalSignature(File input, File output) {
        try {
            InputStream aesInputStream = Encryption.class.getClassLoader().getResourceAsStream("rsa_store.p12");
            KeyStore rsaKeyStore = KeyStore.getInstance("PKCS12");
            rsaKeyStore.load(aesInputStream, properties.getProperty("encryption.rsa.store.pass").toCharArray());
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign((PrivateKey) rsaKeyStore.getKey(
                    properties.getProperty("encryption.rsa.store.alias"),
                    properties.getProperty("encryption.rsa.store.pass").toCharArray()));
            FileInputStream inputStream = new FileInputStream(input);
            signature.update(inputStream.readAllBytes());
            inputStream.close();
            byte[] digitalSignature = signature.sign();
            String fileName = input.getName().split("\\.")[0] + ".signature";
            File signatureStore = new File(output.getAbsolutePath() + "/" + fileName);
            signatureStore.createNewFile();
            FileOutputStream signatureStoreOutputStream = new FileOutputStream(signatureStore);
            signatureStoreOutputStream.write(digitalSignature);
            signatureStoreOutputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public boolean decrypt(File toDecrypt, File outputDir, File signatureFile, File IVFile, Component parent) {
        try {
            if (toDecrypt == null || outputDir == null || IVFile == null) {
                return false;
            }
            FileInputStream ivInputStream = new FileInputStream(IVFile);
            byte[] ivBytes = ivInputStream.readAllBytes();
            ivInputStream.close();
            IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
            InputStream aesKeyIS = Encryption.class.getClassLoader().getResourceAsStream("keystore.jceks");
            KeyStore aesKeyStore = KeyStore.getInstance("PKCS12");
            aesKeyStore.load(aesKeyIS, properties.getProperty("encryption.aes.store.pass").toCharArray());
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, aesKeyStore.getKey(
                    properties.getProperty("encryption.aes.store.alias"),
                    properties.getProperty("encryption.aes.store.pass").toCharArray()
            ), ivParameterSpec);
            FileInputStream toDecryptOS = new FileInputStream(toDecrypt);
            byte[] Base64encodedBytes = toDecryptOS.readAllBytes();
            byte[] decodedBytes = Base64.getDecoder().decode(Base64encodedBytes);
            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            String fileName = toDecrypt.getName().replace(".enc", "");
            File outputFile = new File(outputDir.getAbsolutePath() + "/" + fileName);
            outputFile.createNewFile();
            FileOutputStream outputStream = new FileOutputStream(outputFile);
            outputStream.write(decryptedBytes);
            outputStream.close();
            verifySignature(decryptedBytes, signatureFile, parent);
            toDecrypt.delete();
            IVFile.delete();
            return true;
        } catch (Exception e) {
            JOptionPane.showConfirmDialog(parent, "Error decrypting the file.", "Error", JOptionPane.DEFAULT_OPTION, JOptionPane.ERROR_MESSAGE);
            e.printStackTrace();
            return false;
        }
    }
    private void verifySignature(byte[] decryptedBytes, File digitalSignature, Component parent) {
        if (digitalSignature == null) {
            JOptionPane.showConfirmDialog(parent, "File decrypted, but no signature was provided.", "Warning", JOptionPane.DEFAULT_OPTION, JOptionPane.WARNING_MESSAGE);
            return;
        }
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            InputStream rsaPublicIS = Encryption.class.getClassLoader().getResourceAsStream("public_store.p12");
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(rsaPublicIS, properties.getProperty("encryption.rsa.store.pass").toCharArray());
            Certificate certificate = store.getCertificate(properties.getProperty("encyption.rsa.store.public.alias"));
            PublicKey publicKey = certificate.getPublicKey();
            signature.initVerify(publicKey);
            signature.update(decryptedBytes);
            FileInputStream signatureIS = new FileInputStream(digitalSignature);
            byte[] signatureBytes = signatureIS.readAllBytes();
            signatureIS.close();
            boolean isCorrect = signature.verify(signatureBytes);
            if (isCorrect) {
                JOptionPane.showConfirmDialog(parent, "File decrypted.", "Success", JOptionPane.DEFAULT_OPTION, JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showConfirmDialog(parent, "File decrypted but signature doesn't match!", "Warning", JOptionPane.DEFAULT_OPTION, JOptionPane.WARNING_MESSAGE);
            }
            digitalSignature.delete();
        } catch (Exception e) {
            JOptionPane.showConfirmDialog(parent, "Error verifying the signature.", "Error", JOptionPane.DEFAULT_OPTION, JOptionPane.ERROR_MESSAGE);
            e.printStackTrace();
        }
    }
}

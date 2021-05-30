package org.yisus.utils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.*;
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
            fileName = toEncrypt.getName().split("\\.")[0] + ".txt";
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
}

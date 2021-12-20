package com.thedeveloperfriend.javasecurity.demosnippets;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

//Note: use the following command to generate private/public keys into a key store (done by sender for ex: rajesh)
// keytool -genkeypair -alias RajeshKeyPair -keyalg RSA -keysize 2048 -dname "CN=thedeveloperfriend.com" -validity 365 -storetype PKCS12 -keystore rajesh_keystore.p12 -storepass changeit

//Note: use the following command to export certificate from key store (done by sender for ex: rajesh)
//keytool -exportcert -alias RajeshKeyPair -storetype PKCS12 -keystore rajesh_keystore.p12 -file rajesh_certificate.cer -rfc -storepass changeit

//Note: use the following command to import certificate into a key store (done by receiver for ex: balu)
//keytool -importcert -alias BaluKeyPair -storetype PKCS12 -keystore balu_keystore.p12 -file rajesh_certificate.cer -rfc -storepass changeit

public class DigitalCertificateDemo {

	public static void main(String[] args) {
		try {
			PrivateKey privateKey = getPrivateKeyFromKeyStore();
			PublicKey publicKey = getPublicKeyFromKeyStore();

			byte[] digitalSignature = createDigitalSignature("test message by rajesh", privateKey);
			boolean isValidSignature = doVerifyDigitalSignature(digitalSignature, "test message by rajesh", publicKey);
			System.out.println("----isValidSignature = " + isValidSignature);

		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
	}

	public static byte[] createDigitalSignature(String message, PrivateKey privateKey) throws NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
		byte[] messageBytes = message.getBytes();
		MessageDigest messageDigest = MessageDigest.getInstance("SHA256");
		byte[] messageHash = messageDigest.digest(messageBytes);

		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		byte[] digitalSignature = cipher.doFinal(messageHash);

		return digitalSignature;
	}

	public static boolean doVerifyDigitalSignature(byte[] digitalSignature, String message, PublicKey publicKey)
			throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
			InvalidKeyException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		byte[] decryptedMessageHash = cipher.doFinal(digitalSignature);

		byte[] messageBytes = message.getBytes();
		MessageDigest messageDigest = MessageDigest.getInstance("SHA256");
		byte[] messageHash = messageDigest.digest(messageBytes);

		boolean isValid = Arrays.equals(decryptedMessageHash, messageHash);

		return isValid;
	}

	public static PrivateKey getPrivateKeyFromKeyStore() throws KeyStoreException, NoSuchAlgorithmException,
			CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException {
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(
				new FileInputStream(
						"C:\\eclipse-workspace\\JavaSecurityDemoCodeSnippets\\src\\main\\java\\rajesh_keystore.p12"),
				"changeit".toCharArray());
		PrivateKey privateKey = (PrivateKey) keyStore.getKey("RajeshKeyPair", "changeit".toCharArray());
		return privateKey;
	}

	public static PublicKey getPublicKeyFromKeyStore() throws NoSuchAlgorithmException, CertificateException,
			FileNotFoundException, IOException, KeyStoreException {

		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(
				new FileInputStream(
						"C:\\eclipse-workspace\\JavaSecurityDemoCodeSnippets\\src\\main\\java\\balu_keystore.p12"),
				"changeit".toCharArray());
		Certificate certificate = keyStore.getCertificate("BaluKeyPair");
		PublicKey publicKey = certificate.getPublicKey();
		return publicKey;

	}

}

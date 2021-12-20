package com.thedeveloperfriend.javasecurity.demosnippets;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricCryptographyTest {

	public static String doEncryptWithAES(String inputString, String key)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, InvalidAlgorithmParameterException {

		byte[] keyAsByteArray = Base64.getDecoder().decode(key);
		Key secrectKey = new SecretKeySpec(keyAsByteArray, 0, keyAsByteArray.length, "AES");

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

		// this 16 byte random string is used for CBC (Cyber Block Chaining).
		byte[] random = "1234567890123456".getBytes();
		IvParameterSpec ivParameterSpec = new IvParameterSpec(random);

		cipher.init(Cipher.ENCRYPT_MODE, secrectKey, ivParameterSpec);

		byte[] inputByteArray = inputString.getBytes();

		byte[] encryptedByteArray = cipher.doFinal(inputByteArray);

		String encryptedString = Base64.getEncoder().encodeToString(encryptedByteArray);

		return encryptedString;

	}

	public static String doDecryptWithAES(String encryptedString, String key)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, InvalidAlgorithmParameterException {
		byte[] keyAsByteArray = Base64.getDecoder().decode(key);
		Key secrectKey = new SecretKeySpec(keyAsByteArray, 0, keyAsByteArray.length, "AES");
		byte[] encryptedByteArray = Base64.getDecoder().decode(encryptedString);

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		// this 16 byte random string is used for CBC (Cyber Block Chaining).
		byte[] random = "1234567890123456".getBytes();
		IvParameterSpec ivParameterSpec = new IvParameterSpec(random);
		cipher.init(Cipher.DECRYPT_MODE, secrectKey, ivParameterSpec);

		byte[] decryptedByteArray = cipher.doFinal(encryptedByteArray);

		StringBuilder buffer = new StringBuilder();
		for (int i = 0; i < decryptedByteArray.length; i++) {
			buffer.append((char) decryptedByteArray[i]);
		}
		String decryptedString = buffer.toString();

		return decryptedString;
	}

	public static String getAESKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(128);
		Key key = keyGenerator.generateKey();
		String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
		return encodedKey;

	}

	public static void main(String[] args) {

		String symmetricKeyString;
		try {
			symmetricKeyString = getAESKey();

			System.out.println("symmetricKeyString = " + symmetricKeyString);

			String encryptedString = doEncryptWithAES("this is test by rajesh kumar raj!!!", symmetricKeyString);

			System.out.println("encryptedString  = " + encryptedString);

			String decryptedString = doDecryptWithAES(encryptedString, symmetricKeyString);
			System.out.println("decryptedString = " + decryptedString);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
	}

}

package com.thedeveloperfriend.javasecurity.demosnippets;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class AsymmetricCryptographicDemo {

	public static byte[] doEncryptWithRSA(byte[] symmetricKeyByteArray, PublicKey publicKey)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");

		cipher.init(Cipher.PUBLIC_KEY, publicKey);

		byte[] encryptedByteArray = cipher.doFinal(symmetricKeyByteArray);

		return encryptedByteArray;
	}

	public static byte[] doDecryptWithRSA(byte[] encryptedByteArray, PrivateKey privateKey)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");

		cipher.init(Cipher.PRIVATE_KEY, privateKey);

		byte[] decryptedByteArray = cipher.doFinal(encryptedByteArray);
		return decryptedByteArray;
	}

	public static KeyPair getRSAKeyPair() throws NoSuchAlgorithmException {

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		java.security.KeyPair keyPair = keyPairGenerator.generateKeyPair();

		return keyPair;
	}

	public static void main(String[] args) {
		try {

			KeyPair keyPair = getRSAKeyPair();

			// Generate a symmetric key. that will act as plain text
			KeyGenerator generator = KeyGenerator.getInstance("AES");
			generator.init(128); // The AES key size in number of bits
			SecretKey secKey = generator.generateKey();
			System.out.println("----Input symmetric key =	" + Arrays.toString(secKey.getEncoded()));

			byte[] encryptedByteArray = doEncryptWithRSA(secKey.getEncoded(), keyPair.getPublic());

			byte[] decryptedByteArray = doDecryptWithRSA(encryptedByteArray, keyPair.getPrivate());
			System.out.println("----decrypted symmetric key=	" + Arrays.toString(decryptedByteArray));

		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
	}

}

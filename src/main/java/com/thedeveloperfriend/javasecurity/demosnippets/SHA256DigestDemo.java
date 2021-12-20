package com.thedeveloperfriend.javasecurity.demosnippets;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA256DigestDemo {

	public static String doSHA256Hashing(String inputString, String saltString) throws NoSuchAlgorithmException {
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
		messageDigest.update(saltString.getBytes());
		byte[] inputByteArray = inputString.getBytes();
		byte[] digest = messageDigest.digest(inputByteArray);
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < digest.length; i++) {
			sb.append(Integer.toString((digest[i] & 0xff) + 0x100, 16).substring(1));
		}
		return sb.toString();
	}

	public static void main(String[] args) {

		try {
			String digest = doSHA256Hashing("this is test by rajesh kumar raj!!!", "Weblogic@123");
			System.out.println("Digest = " + digest);

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

}

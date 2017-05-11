package com.acme;

import java.util.Base64;
import java.util.Random;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import static javax.crypto.Cipher.ENCRYPT_MODE;
import static javax.crypto.Cipher.DECRYPT_MODE;

public class DecryptionTools {

	public static final String PUBLIC_KEY_ALGORITHM = "RSA";

	public static String KEYSTORE_FILENAME = "keystore.jks";
	public static String CERTIFICATE_ALIAS = "fredflintstone";
	
	/**
	 * Get AES/ECB/NoPadding Cipher
	 * @param encrypt boolean true for Cipher.ENCRYPT_MODE, false for Cipher.DECRYPT_MODE
	 * @param key byte[] Key
	 * @return Cipher
	 * @throws InvalidKeyException
	 */
	public static Cipher getCipher(final boolean encrypt, byte[] key) throws InvalidKeyException {
		Cipher cipher = null;

		try {
			Key k = new SecretKeySpec(key, "AES");
			cipher = Cipher.getInstance("AES/ECB/NoPadding");
			cipher.init(encrypt ? ENCRYPT_MODE : DECRYPT_MODE, k);

		} catch (NoSuchAlgorithmException | NoSuchPaddingException neverthrown) { }
		return cipher;
	}

	/**
	 * Load  JKS key store from InputStream
	 * @param inputStrm InputStream
	 * @param password String Key store password
	 * @return KeyStore
	 * @throws KeyStoreException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 */
	public static KeyStore loadJKSKeyStore(final InputStream inputStrm, final String password)
			throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
		if (null == inputStrm)
			throw new NullPointerException("Input stream cannot be null");
		final KeyStore keystore = KeyStore.getInstance("JKS");
		keystore.load(inputStrm, null == password ? null : password.toCharArray());
		return keystore;
	}

	/**
	 * Get Certificate from JKS key store
	 * @return Certificate
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 */
	public static Certificate getCertificate()
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		KeyStore keystore = loadJKSKeyStore(DecryptionTools.class.getResourceAsStream(KEYSTORE_FILENAME), null);
		return keystore.getCertificate(CERTIFICATE_ALIAS);
	}

	/**
	 * Encrypt a password using RSA certificate and return the encrypted result encoded in Base64
	 * @param password byte[] Password to encrypt
	 * @return String
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws KeyStoreException
	 * @throws CertificateException
	 * @throws IOException
	 */
	public static String encryptPasswordBase64(final byte[] password) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, KeyStoreException, CertificateException, IOException {

		final Cipher rsa = Cipher.getInstance(PUBLIC_KEY_ALGORITHM);
		rsa.init(ENCRYPT_MODE, getCertificate());

		ByteArrayOutputStream byteKey = new ByteArrayOutputStream(512);
		try (CipherOutputStream cipheredKey = new CipherOutputStream(byteKey, rsa)) {
			cipheredKey.write(password);
		}

		return Base64.getEncoder().encodeToString(byteKey.toByteArray());
	}

	/**
	 * Decrypt a Base64 encoded key using a private key
	 * @param password
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws KeyStoreException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws InvalidKeySpecException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] decryptPasswordBase64(final String password) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, KeyStoreException, CertificateException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
		PrivateKey der = getPrivateKey();
		Cipher rsa = Cipher.getInstance(PUBLIC_KEY_ALGORITHM);
		rsa.init(DECRYPT_MODE, der);
		return rsa.doFinal(Base64.getDecoder().decode(password));
	}

	/**
	 * Get PKCS #8 private key in DER format from stream
	 * @return PrivateKey
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static PrivateKey getPrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        InputStream fis = DecryptionTools.class.getResourceAsStream(CERTIFICATE_ALIAS+".der");
    	byte[] keyBytes = new byte[1219];        
        try (DataInputStream dis = new DataInputStream(fis)) {
        	dis.readFully(keyBytes);
        }
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(PUBLIC_KEY_ALGORITHM);
        return kf.generatePrivate(spec);
    }

	/**
	 * Generate a random key of the given length
	 * @param keyLength int
	 * @return String
	 */
	public static String generateRandomKey(final int keyLength) {

		if (keyLength <= 0)
			throw new StringIndexOutOfBoundsException("Identifier length must be greater than zero");

		final String charsSet = "abcdefghijkmnpqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$%#!@()[]{}";

		final int charsSetSize = charsSet.length();
		StringBuilder oId = new StringBuilder(keyLength);
		Random oRnd = new Random();
		for (int i = 0; i < keyLength; i++)
			oId.append(charsSet.charAt(oRnd.nextInt(charsSetSize)));
		return oId.toString();
	}

}
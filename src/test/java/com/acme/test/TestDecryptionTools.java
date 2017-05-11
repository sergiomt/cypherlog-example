package com.acme.test;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import static java.nio.charset.StandardCharsets.ISO_8859_1;

import com.acme.DecryptionTools;
import static com.acme.DecryptionTools.*;

public class TestDecryptionTools {

	public static final int KEY_LENGTH = 16;

	public static final String CERTIFICATE_ALIAS = "fredflintstone";
	
	@Test
	public void testCipherDecipherKey() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, InvalidKeyException, NoSuchPaddingException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
		
		final String key = generateRandomKey(KEY_LENGTH);
		
		assertEquals(KEY_LENGTH, key.length());

		KeyStore keystore = loadJKSKeyStore(DecryptionTools.class.getResourceAsStream("keystore.jks"), null);
		
		assertNotNull(keystore);
		
		Certificate cert = keystore.getCertificate(CERTIFICATE_ALIAS);
		
		assertNotNull(cert);

		String cipheredKey = encryptPasswordBase64(key.getBytes(ISO_8859_1));
		
		assertNotNull(cipheredKey);
		assertEquals(344, cipheredKey.length());
				
		byte[] decipheredKey = decryptPasswordBase64(cipheredKey);
		assertNotNull(decipheredKey);
		assertNotEquals(0, decipheredKey.length);
		
		assertEquals(key, new String(decipheredKey, ISO_8859_1));
			
	}
}
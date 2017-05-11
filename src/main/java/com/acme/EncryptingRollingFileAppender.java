package com.acme;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;

import org.apache.log4j.Layout;
import org.apache.log4j.RollingFileAppender;

import static java.nio.charset.StandardCharsets.ISO_8859_1;

public class EncryptingRollingFileAppender extends RollingFileAppender {

	private CipherOutputStream s;

	private Cipher cipher;

	private byte[] secretKey;

	public EncryptingRollingFileAppender(Layout layout, String filename, boolean append) throws IOException {
		super(layout, filename, append);
		writeKeyFile(filename);
	}

	public EncryptingRollingFileAppender(Layout layout, String filename) throws IOException {
		super(layout, filename);
		writeKeyFile(filename);
	}

	private void writeKeyFile(final String logfilename) throws IOException {
		final int dot = logfilename.lastIndexOf('.');
		final String keyfilename = (dot==-1 ? logfilename : logfilename.substring(0, dot)) + ".key";
		try (FileOutputStream out = new FileOutputStream(keyfilename)) {
			out.write(DecryptionTools.encryptPasswordBase64(secretKey).getBytes(ISO_8859_1));
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | KeyStoreException | CertificateException e) { }
	}

	@Override
	protected OutputStreamWriter createWriter(OutputStream outputStream) {
		System.out.println("createWriter()");
		if (cipher == null) {
				secretKey = DecryptionTools.generateRandomKey(16).getBytes(ISO_8859_1);
				try {
					cipher = DecryptionTools.getCipher(true, secretKey);
				} catch (InvalidKeyException e) {
					System.out.println("InvalidKeyException");
				}
				s = new CipherOutputStream(outputStream, cipher);
		}
		
		OutputStreamWriter out = super.createWriter(s);
		return out;
	}
}

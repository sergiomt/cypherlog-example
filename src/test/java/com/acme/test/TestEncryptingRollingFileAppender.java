package com.acme.test;

import org.junit.Test;

import com.acme.EncryptingRollingFileAppender;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.log4j.Logger;
import org.apache.log4j.Priority;
import org.apache.log4j.LogManager;
import org.apache.log4j.SimpleLayout;
import org.apache.log4j.spi.LoggingEvent;

import static com.acme.DecryptionTools.getCipher;
import static com.acme.DecryptionTools.decryptPasswordBase64;

public class TestEncryptingRollingFileAppender {

	@SuppressWarnings("deprecation")
	@Test
	public void testAppender() throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, KeyStoreException, CertificateException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {

		final File logfile = File.createTempFile("testlog_", ".log");
		final String logfilename = logfile.getAbsolutePath();
		
		final Logger lggr = LogManager.getLogger(TestEncryptingRollingFileAppender.class);
		final EncryptingRollingFileAppender appender = new EncryptingRollingFileAppender(new SimpleLayout(), logfilename, true);
		
		appender.append(new LoggingEvent(lggr.getClass().getName(), lggr, Priority.INFO, "Test Log Line #1", null));
		appender.append(new LoggingEvent(lggr.getClass().getName(), lggr, Priority.INFO, "Test Log Line #1", null));

		final int dot = logfilename.lastIndexOf('.');
		byte[] key = decryptPasswordBase64(new String(Files.readAllBytes(Paths.get(logfilename.substring(0, dot)+".key"))));
		
		StringBuilder logContent = new StringBuilder();
		try (FileInputStream instrm = new FileInputStream(logfilename);
			 CipherInputStream cistrm = new CipherInputStream(instrm, getCipher(false, key))) {
			int c;
			while ((c=cistrm.read())!=-1)
				logContent.append((char) c);
		}

		assertEquals("INFO - Test Log Line #1\r\nINFO - Test Log Line #1", logContent.toString());
		
		logfile.delete();
		new File(logfilename.substring(0, logfilename.lastIndexOf('.'))+".key").delete();
	}
}

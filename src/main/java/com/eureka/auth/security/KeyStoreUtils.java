package com.eureka.auth.security;

import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

@Component
public class KeyStoreUtils {
	
	
	 @Value("${keystore.location}")
	   private Resource resourceFile;
	 
	public  Key readPrivateKey() throws IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, KeyStoreException {
		  InputStream is = resourceFile.getInputStream();
		  String privateKeyString="";
	      KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
	      String password = "test@123";
	      char[] passwd = password.toCharArray();
	      keystore.load(is, passwd);
	      String alias = "keubiko";
	      Key key = keystore.getKey(alias, passwd);
			/*
			 * if (key instanceof PublicKey) { // Get certificate of public key Certificate
			 * cert = keystore.getCertificate(alias); // Get public key PublicKey publicKey
			 * = cert.getPublicKey(); String publicKeyString =
			 * Base64.encodeBase64String(publicKey .getEncoded());
			 * System.out.println("--> "+publicKeyString); } if (key instanceof PrivateKey)
			 * { // Get certificate of public key Certificate cert =
			 * keystore.getCertificate(alias);
			 * 
			 * // Get public key PublicKey publicKey = cert.getPublicKey(); String
			 * publicKeyString = Base64.encodeBase64String(publicKey .getEncoded());
			 * 
			 * KeyPair keyPair= new KeyPair(publicKey, (PrivateKey) key);
			 * 
			 * privateKeyString = Base64.encodeBase64String(((PrivateKey) key
			 * ).getEncoded());
			 * 
			 * }
			 */
	      return key;
	  }

}

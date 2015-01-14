package com.hypersocket.crypto;

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.KeyAgreement;

public interface ECCryptoProvider {

	void init(String curve);
	
	KeyAgreement createKeyAgreement(KeyPair keyPair)
			throws NoSuchAlgorithmException, NoSuchProviderException,
			InvalidAlgorithmParameterException, InvalidKeyException;

	KeyPair generateKeyPair() throws NoSuchAlgorithmException,
			NoSuchProviderException, InvalidAlgorithmParameterException;

	byte[] generateQ(PublicKey ec);

	PublicKey decodePublicKey(byte[] publicKey) throws InvalidKeySpecException,
			NoSuchAlgorithmException, NoSuchProviderException;

	PublicKey decodeKey(byte[] encoded) throws InvalidKeySpecException,
			NoSuchAlgorithmException, NoSuchProviderException;

	byte[] sign(PrivateKey key, byte[] data) throws IOException,
			NoSuchAlgorithmException, NoSuchProviderException,
			SignatureException, InvalidKeyException;

	boolean verify(PublicKey key, byte[] signature, byte[] data)
			throws IOException, NoSuchAlgorithmException,
			NoSuchProviderException, SignatureException, InvalidKeyException;

	void saveKeyPair(KeyPair pair, File keyfile) throws IOException;

	KeyPair loadKeyPair(File keyfile) throws IOException;

}

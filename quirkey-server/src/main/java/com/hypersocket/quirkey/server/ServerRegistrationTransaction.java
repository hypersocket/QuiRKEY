package com.hypersocket.quirkey.server;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.util.UUID;

import javax.crypto.KeyAgreement;

import org.apache.commons.codec.binary.Base64;

import com.hypersocket.crypto.ByteArrayReader;
import com.hypersocket.crypto.ByteArrayWriter;
import com.hypersocket.crypto.ECCryptoProvider;
import com.hypersocket.crypto.ECCryptoProviderFactory;
import com.hypersocket.crypto.QuiRKEYTransaction;

public class ServerRegistrationTransaction extends QuiRKEYTransaction {

	static final String EC_CURVE = "secp256r1";
	
	KeyAgreement keyAgreement;
	byte[] Q_C;
	String username;
	URL serverURL;
	KeyPair serverKey;
	String registrationId;
	PublicKey ec;
	ECCryptoProvider ecProvider;
	
	public ServerRegistrationTransaction(String username, URL serverURL, KeyPair serverKey, String curve)
			throws InvalidAlgorithmParameterException,
			NoSuchAlgorithmException, NoSuchProviderException,
			InvalidKeyException {

		this.username = username;
		this.serverURL = serverURL;
		this.serverKey = serverKey;
		
		ecProvider = ECCryptoProviderFactory.createInstance(curve);
		KeyPair ecdhKeyPair = ecProvider.generateKeyPair();
		this.keyAgreement = ecProvider.createKeyAgreement(ecdhKeyPair);
		this.ec = ecdhKeyPair.getPublic();
		this.Q_C = ecProvider.generateQ(ec);
		this.registrationId = UUID.randomUUID().toString();

	}

	public String generateRegistrationInfo() throws IOException {
		ByteArrayWriter msg = new ByteArrayWriter();

		try {
			msg.writeString(registrationId);
			msg.writeString(username);
			msg.writeString(serverURL.toExternalForm());
			msg.writeBinaryString(Q_C);
			msg.writeBinaryString(serverKey.getPublic().getEncoded());

			return Base64.encodeBase64String(msg.toByteArray());
		} finally {
			msg.close();
		}
	}

	public String verifyResponse(String encodedResponse) throws IOException {

		ByteArrayReader reader = new ByteArrayReader(
				Base64.decodeBase64(encodedResponse));

		try {

			String registrationId = reader.readString();
			String mobileId = reader.readString();
			String mobileName = reader.readString();
			byte[] Q_S = reader.readBinaryString();
			byte[] clientKey = reader.readBinaryString();

			byte[] signature = reader.readBinaryString();

			PublicKey clientPublicKey = ecProvider.decodePublicKey(clientKey);
			keyAgreement.doPhase(ecProvider.decodeKey(Q_S), true);

			byte[] tmp = keyAgreement.generateSecret();
			if ((tmp[0] & 0x80) == 0x80) {
				byte[] tmp2 = new byte[tmp.length + 1];
				System.arraycopy(tmp, 0, tmp2, 1, tmp.length);
				tmp = tmp2;
			}

			// Calculate diffe hellman k value
			BigInteger secret = new BigInteger(tmp);

			byte[] exchangeHash = generateExchangeHash(Q_C, Q_S, serverKey
					.getPublic().getEncoded(), clientKey, username, mobileId,
					registrationId, secret, mobileName,
					serverURL.toExternalForm());

			if (!ecProvider.verify(clientPublicKey, signature, exchangeHash)) {
				throw new Exception("Invalid client signature");
			}

			ByteArrayWriter writer = new ByteArrayWriter();

			ByteArrayWriter signatureResponse = new ByteArrayWriter();

			try {
				writer.writeBinaryString(ecProvider.sign(
						serverKey.getPrivate(), exchangeHash));

				return Base64.encodeBase64String(writer.toByteArray());

			} finally {
				writer.close();
				signatureResponse.close();
			}
		} catch (Exception e) {
			throw new IOException(e);
		} finally {
			reader.close();
		}
	}
}

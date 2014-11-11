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

public class ServerAuthenticationTransaction extends QuiRKEYTransaction {

	static final String EC_CURVE = "secp256r1";

	KeyAgreement keyAgreement;
	byte[] Q_C;
	URL serverURL;
	String authenticationId;
	PublicKey ec;
	ECCryptoProvider ecProvider;

	public ServerAuthenticationTransaction(URL serverURL, KeyPair serverKey,
			String curve) throws InvalidAlgorithmParameterException,
			NoSuchAlgorithmException, NoSuchProviderException,
			InvalidKeyException {

		this.serverURL = serverURL;

		ecProvider = ECCryptoProviderFactory.createInstance(curve);
		KeyPair ecdhKeyPair = ecProvider.generateKeyPair();
		this.keyAgreement = ecProvider.createKeyAgreement(ecdhKeyPair);
		this.ec = ecdhKeyPair.getPublic();
		this.Q_C = ecProvider.generateQ(ec);
		this.authenticationId = UUID.randomUUID().toString();

	}

	public String getAuthenticationId() {
		return authenticationId;
	}

	public String generateAuthenticationInfo() throws IOException {
		ByteArrayWriter msg = new ByteArrayWriter();

		try {
			msg.writeString(authenticationId);
			msg.writeString(serverURL.toExternalForm());
			msg.writeBinaryString(Q_C);

			return Base64.encodeBase64String(msg.toByteArray());
		} finally {
			msg.close();
		}
	}

	public boolean verifyResponse(String encodedResponse, KeyPair serverKey, String username) throws IOException {

		ByteArrayReader reader = new ByteArrayReader(
				Base64.decodeBase64(encodedResponse));

		try {

			authenticationId = reader.readString();
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
					authenticationId, secret, mobileName,
					serverURL.toExternalForm());

			return ecProvider.verify(clientPublicKey, signature, exchangeHash);
		} catch (Exception e) {
			throw new IOException(e);
		} finally {
			reader.close();
		}
	}
}

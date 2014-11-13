package com.hypersocket.quirkey.server;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;
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
	String mobileId;
	byte[] Q_S;
	byte[] signature;
	PublicKey clientPublicKey;
	String status;
	Date creationDate;

	public ServerAuthenticationTransaction(URL serverURL, String curve)
			throws InvalidAlgorithmParameterException,
			NoSuchAlgorithmException, NoSuchProviderException,
			InvalidKeyException {

		this.serverURL = serverURL;

		ecProvider = ECCryptoProviderFactory.createInstance(curve);
		KeyPair ecdhKeyPair = ecProvider.generateKeyPair();
		this.keyAgreement = ecProvider.createKeyAgreement(ecdhKeyPair);
		this.ec = ecdhKeyPair.getPublic();
		this.Q_C = ecProvider.generateQ(ec);
		this.authenticationId = UUID.randomUUID().toString();
		this.creationDate = new Date();
		this.status = "in progress";

	}

	public String getAuthenticationId() {
		return authenticationId;
	}

	public String getStatus() {
		return status;
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

	public static String getAuthenticationId(String encodedResponse)
			throws IOException {
		ByteArrayReader reader = new ByteArrayReader(
				Base64.decodeBase64(encodedResponse));
		try {
			return reader.readString();

		} catch (IOException e) {
			throw new IOException(e);
		} finally {
			reader.close();
		}
	}

	private void readData(String encodedResponse) throws IOException {
		ByteArrayReader reader = new ByteArrayReader(
				Base64.decodeBase64(encodedResponse));
		try {
			authenticationId = reader.readString();
			mobileId = reader.readString();
			Q_S = reader.readBinaryString();
			signature = reader.readBinaryString();
		} catch (IOException e) {
			throw new IOException(e);
		} finally {
			reader.close();
		}

	}

	public String getMobileId(String encodedResponse) throws IOException {
		readData(encodedResponse);
		return mobileId;
	}

	public String verifyResponse(String encodedResponse,
			byte[] serverPrivateKey, byte[] serverPublicKey, String username,
			String mobileName, byte[] clientKey) throws IOException {

		readData(encodedResponse);
		try {

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

			byte[] exchangeHash = generateExchangeHash(Q_C, Q_S,
					serverPublicKey, clientKey, username, mobileId,
					authenticationId, secret, mobileName,
					serverURL.toExternalForm());

			if (!ecProvider.verify(clientPublicKey, signature, exchangeHash)) {
				this.status = "failed";
				throw new Exception("Invalid client signature");
			}

			ByteArrayWriter writer = new ByteArrayWriter();

			ByteArrayWriter signatureResponse = new ByteArrayWriter();

			try {

				KeyFactory kf = KeyFactory.getInstance("EC");
				writer.writeBinaryString(ecProvider.sign(kf
						.generatePrivate(new PKCS8EncodedKeySpec(
								serverPrivateKey)), exchangeHash));
				this.status = "success";
				return Base64.encodeBase64String(writer.toByteArray());

			} finally {
				writer.close();
				signatureResponse.close();
			}
		} catch (Exception e) {
			throw new IOException(e);
		}
	}
}

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
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;

import javax.crypto.KeyAgreement;

import org.apache.commons.codec.binary.Base64;

import com.hypersocket.crypto.ByteArrayReader;
import com.hypersocket.crypto.ByteArrayWriter;
import com.hypersocket.crypto.ECCryptoProvider;
import com.hypersocket.crypto.ECCryptoProviderFactory;
import com.hypersocket.crypto.QuiRKEYException;
import com.hypersocket.crypto.QuiRKEYTransaction;

public class ServerAuthenticationTransaction extends QuiRKEYTransaction {

	static final String EC_CURVE = "secp256r1";

	KeyAgreement keyAgreement;
	byte[] Q_C;
	URL serverURL;
	int authenticationId;
	PublicKey ec;
	ECCryptoProvider ecProvider;
	String mobileId;
	byte[] Q_S;
	byte[] signature;
	PublicKey clientPublicKey;
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
		this.authenticationId = new SecureRandom().nextInt();
		this.creationDate = new Date();
	}

	public int getAuthenticationId() {
		return authenticationId;
	}

	public Date getCreationDate() {
		return creationDate;
	}

	public String generateAuthenticationInfo() throws IOException {
		ByteArrayWriter msg = new ByteArrayWriter();

		try {
			msg.write(MSG_AUTHENTICATION_INFO);
			msg.writeInt(authenticationId);
			msg.writeString(serverURL.toExternalForm());
			msg.writeBinaryString(Q_C);

			return Base64.encodeBase64String(msg.toByteArray());
		} finally {
			msg.close();
		}
	}

	public String getMobileId() throws IOException {
		return mobileId;
	}

	public String generateErrorMessage(int errorCode, String errorDesc)
			throws IOException {

		ByteArrayWriter msg = new ByteArrayWriter();

		try {
			msg.write(MSG_AUTHENTICATION_FAILURE);
			msg.writeInt(errorCode);
			msg.writeString(errorDesc);

			return Base64.encodeBase64String(msg.toByteArray());
		} finally {
			msg.close();
		}
	}

	public String processAuthenticationRequest(String encodedResponse,
			byte[] serverPrivateKey, byte[] serverPublicKey, String username,
			String mobileName, byte[] clientKey) throws IOException,
			QuiRKEYException {

		ByteArrayReader reader = new ByteArrayReader(
				Base64.decodeBase64(encodedResponse));
		try {
			int messageid = reader.read();
			if (messageid != MSG_AUTHENTICATION_PROCESS) {
				if (messageid == MSG_AUTHENTICATION_FAILURE) {
					throw new QuiRKEYException((int) reader.readInt(),
							reader.readString());
				} else {
					throw new IOException("Unexpected message id " + messageid
							+ " in registration flow");
				}
			}
			authenticationId = (int) reader.readInt();
			mobileId = reader.readString();
			Q_S = reader.readBinaryString();
			signature = reader.readBinaryString();
		} finally {
			reader.close();
		}

		ByteArrayWriter writer = new ByteArrayWriter();
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
				throw new IOException("Invalid client signature");
			}

			ByteArrayWriter signatureResponse = new ByteArrayWriter();

			try {

				KeyFactory kf = KeyFactory.getInstance("EC");
				writer.write(MSG_AUTHENTICATION_SUCCESS);
				writer.writeBinaryString(ecProvider.sign(kf
						.generatePrivate(new PKCS8EncodedKeySpec(
								serverPrivateKey)), exchangeHash));
				return Base64.encodeBase64String(writer.toByteArray());

			} finally {

				signatureResponse.close();
			}
		} catch (NoSuchAlgorithmException | NoSuchProviderException
				| InvalidKeySpecException | InvalidKeyException
				| IllegalStateException | SignatureException e) {
			throw new IOException(e);
		} finally {
			writer.close();
		}
	}
}

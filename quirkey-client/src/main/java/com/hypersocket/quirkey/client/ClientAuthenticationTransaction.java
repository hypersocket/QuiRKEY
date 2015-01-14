package com.hypersocket.quirkey.client;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.KeyAgreement;

import org.spongycastle.util.encoders.Base64;

import com.hypersocket.crypto.ByteArrayReader;
import com.hypersocket.crypto.ByteArrayWriter;
import com.hypersocket.crypto.ECCryptoProvider;
import com.hypersocket.crypto.ECCryptoProviderFactory;
import com.hypersocket.crypto.QuiRKEYException;
import com.hypersocket.crypto.QuiRKEYTransaction;

public class ClientAuthenticationTransaction extends QuiRKEYTransaction {

	int authenticationId;
	String url;
	byte[] Q_C;
	byte[] Q_S;
	byte[] clientExchangeHash;
	BigInteger secret;
	ECCryptoProvider ecProvider;
	KeyAgreement keyAgreement;
	String transactionType;

	public ClientAuthenticationTransaction(String encodedAuthentication,
			String curve) throws QuiRKEYException, IOException {

		this.ecProvider = ECCryptoProviderFactory.createInstance(curve);
		ByteArrayReader reader = new ByteArrayReader(
				Base64.decode(encodedAuthentication));

		try {
			int messageId = reader.read();
			if (messageId != MSG_AUTHENTICATION_INFO) {
				if (messageId == MSG_AUTHENTICATION_FAILURE) {
					throw new QuiRKEYException((int) reader.readInt(),
							reader.readString());
				} else {
					throw new IOException("Unexpected message id " + messageId
							+ " in registration flow");
				}
			}
			authenticationId = (int) reader.readInt();
			url = reader.readString();
			Q_C = reader.readBinaryString();

			KeyPair ecdhKeyPair = ecProvider.generateKeyPair();
			this.keyAgreement = ecProvider.createKeyAgreement(ecdhKeyPair);

			PublicKey ec = ecdhKeyPair.getPublic();
			Q_S = ecProvider.generateQ(ec);

			keyAgreement.doPhase(ecProvider.decodeKey(Q_C), true);

			byte[] tmp = keyAgreement.generateSecret();
			if ((tmp[0] & 0x80) == 0x80) {
				byte[] tmp2 = new byte[tmp.length + 1];
				System.arraycopy(tmp, 0, tmp2, 1, tmp.length);
				tmp = tmp2;
			}

			// Calculate diffe hellman k value
			secret = new BigInteger(tmp);
		} catch (NoSuchAlgorithmException | NoSuchProviderException
				| InvalidAlgorithmParameterException | InvalidKeyException
				| IllegalStateException | InvalidKeySpecException e) {
			throw new IOException(e);
		} finally {
			reader.close();
		}

	}

	public int getAuthenticationId() {
		return authenticationId;
	}

	public String getUrl() {
		return url;
	}

	public String getTransactionType() {
		return transactionType;
	}

	public String generateAuthenticationRequest(String mobileId,
			String mobileName, byte[] serverPublicKey, String username,
			byte[] clientPrivateKey, byte[] clientPublicKey) throws IOException {

		ByteArrayWriter writer = new ByteArrayWriter();

		try {
			writer.write(MSG_AUTHENTICATION_PROCESS);
			writer.writeInt(authenticationId);
			writer.writeString(mobileId);
			writer.writeBinaryString(Q_S);

			clientExchangeHash = generateExchangeHash(Q_C, Q_S,
					serverPublicKey, clientPublicKey, username, mobileId,
					authenticationId, secret, mobileName, url);

			KeyFactory kf = KeyFactory.getInstance("EC");
			writer.writeBinaryString(ecProvider.sign(
					kf.generatePrivate(new PKCS8EncodedKeySpec(clientPrivateKey)),
					clientExchangeHash));

			return Base64.toBase64String(writer.toByteArray());
		} catch (NoSuchAlgorithmException | NoSuchProviderException
				| InvalidKeyException | SignatureException
				| InvalidKeySpecException e) {
			throw new IOException(e);
		} finally {
			writer.close();
		}
	}

	public boolean verifyAuthenticationResponse(String encodedResponse,
			byte[] serverPublicKey) throws IOException, QuiRKEYException {

		ByteArrayReader reader = new ByteArrayReader(
				Base64.decode(encodedResponse));

		try {
			int messageId = reader.read();

			if (messageId != MSG_AUTHENTICATION_SUCCESS) {
				if (messageId == MSG_AUTHENTICATION_FAILURE) {
					throw new QuiRKEYException((int) reader.readInt(),
							reader.readString());
				} else {
					throw new IOException("Unexpected message id " + messageId
							+ " in registration flow");
				}
			}

			byte[] signature = reader.readBinaryString();

			PublicKey publicKey = ecProvider.decodePublicKey(serverPublicKey);
			return ecProvider.verify(publicKey, signature, clientExchangeHash);
		} catch (InvalidKeySpecException | NoSuchAlgorithmException
				| NoSuchProviderException | InvalidKeyException | SignatureException e) {
			throw new IOException(e);
		} finally {
			reader.close();
		}
	}
}

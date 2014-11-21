package com.hypersocket.quirkey.client;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.KeyAgreement;

import org.spongycastle.util.encoders.Base64;

import com.hypersocket.crypto.ByteArrayReader;
import com.hypersocket.crypto.ByteArrayWriter;
import com.hypersocket.crypto.ECCryptoProvider;
import com.hypersocket.crypto.ECCryptoProviderFactory;
import com.hypersocket.crypto.QuiRKEYTransaction;

public class ClientAuthenticationTransaction extends QuiRKEYTransaction {

	String authenticationId;
	String url;
	byte[] Q_C;
	byte[] Q_S;
	byte[] clientExchangeHash;
	BigInteger secret;
	ECCryptoProvider ecProvider;
	KeyAgreement keyAgreement;
	String transactionType;

	public ClientAuthenticationTransaction(String encodedAuthentication,
			String curve) throws QuiRKEYAuthenticationException, IOException {

		this.ecProvider = ECCryptoProviderFactory.createInstance(curve);
		ByteArrayReader reader = new ByteArrayReader(
				Base64.decode(encodedAuthentication));

		try {
			transactionType = reader.readString();
			if (!"2".equals(transactionType)) {
				throw new QuiRKEYAuthenticationException("Transaction error");
			}
			authenticationId = reader.readString();
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
		} catch (QuiRKEYAuthenticationException e) {
			throw e;
		} catch (Exception e) {
			throw new IOException(e);
		} finally {
			reader.close();
		}

	}

	public String getAuthenticationId() {
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

			writer.writeString(authenticationId);
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
		} catch (Exception e) {
			throw new IOException(e);
		} finally {
			writer.close();
		}
	}

	public boolean verifyAuthenticationResponse(String encodedResponse,
			byte[] serverPublicKey) throws IOException,
			QuiRKEYAuthenticationException {

		ByteArrayReader reader = new ByteArrayReader(
				Base64.decode(encodedResponse));
		String errorCode = reader.readString();

		try {
			if (!"0".equals(errorCode)) {
				throw new QuiRKEYAuthenticationException(errorCode);
			}

			byte[] signature = reader.readBinaryString();

			PublicKey publicKey = ecProvider.decodePublicKey(serverPublicKey);
			return ecProvider.verify(publicKey, signature, clientExchangeHash);
		} catch (QuiRKEYAuthenticationException e) {
			throw e;
		} catch (Exception e) {
			throw new IOException(e);
		} finally {
			reader.close();
		}
	}
}

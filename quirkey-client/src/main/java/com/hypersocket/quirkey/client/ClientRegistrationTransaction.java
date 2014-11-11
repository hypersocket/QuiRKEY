package com.hypersocket.quirkey.client;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;

import javax.crypto.KeyAgreement;

import org.spongycastle.util.encoders.Base64;

import com.hypersocket.crypto.ByteArrayReader;
import com.hypersocket.crypto.ByteArrayWriter;
import com.hypersocket.crypto.ECCryptoProvider;
import com.hypersocket.crypto.ECCryptoProviderFactory;
import com.hypersocket.crypto.QuiRKEYTransaction;

public class ClientRegistrationTransaction extends QuiRKEYTransaction {

	String registrationId;
	String username;
	String url;
	byte[] Q_C;
	byte[] Q_S;
	byte[] serverPublicKey;
	byte[] clientExchangeHash;
	BigInteger secret;
	KeyPair clientKeyPair;
	ECCryptoProvider ecProvider;
	KeyAgreement keyAgreement;

	public ClientRegistrationTransaction(KeyPair clientKeyPair,
			String encodedRegistration, String curve) throws IOException {

		this.clientKeyPair = clientKeyPair;
		this.ecProvider = ECCryptoProviderFactory.createInstance(curve);
		ByteArrayReader reader = new ByteArrayReader(
				Base64.decode(encodedRegistration));

		try {
			registrationId = reader.readString();
			username = reader.readString();
			url = reader.readString();
			Q_C = reader.readBinaryString();
			serverPublicKey = reader.readBinaryString();

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
		} catch (Exception e) {
			throw new IOException(e);
		} finally {
			reader.close();
		}

	}

	public String getRegistrationId() {
		return registrationId;
	}

	public String getUsername() {
		return username;
	}

	public String getUrl() {
		return url;
	}

	public byte[] getServerPublicKey() {
		return serverPublicKey;
	}

	public String generateRegistrationRequest(String mobileId, String mobileName)
			throws IOException {

		ByteArrayWriter writer = new ByteArrayWriter();

		try {

			writer.writeString(registrationId);
			writer.writeString(mobileId);
			writer.writeString(mobileName);
			writer.writeBinaryString(Q_S);
			writer.writeBinaryString(clientKeyPair.getPublic().getEncoded());

			clientExchangeHash = generateExchangeHash(Q_C, Q_S,
					serverPublicKey, clientKeyPair.getPublic().getEncoded(),
					username, mobileId, registrationId, secret, mobileName, url);

			writer.writeBinaryString(ecProvider.sign(
					clientKeyPair.getPrivate(), clientExchangeHash));

			return Base64.toBase64String(writer.toByteArray());
		} catch (Exception e) {
			throw new IOException(e);
		} finally {
			writer.close();
		}
	}

	public boolean verifyRegistrationResponse(String encodedResponse)
			throws IOException {

		ByteArrayReader reader = new ByteArrayReader(
				Base64.decode(encodedResponse));

		try {
			byte[] signature = reader.readBinaryString();

			PublicKey publicKey = ecProvider.decodePublicKey(serverPublicKey);
			return ecProvider.verify(publicKey, signature, clientExchangeHash);
		} catch (Exception e) {
			throw new IOException(e);
		} finally {
			reader.close();
		}
	}
}

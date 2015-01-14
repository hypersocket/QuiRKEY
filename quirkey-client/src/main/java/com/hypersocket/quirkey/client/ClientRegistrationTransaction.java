package com.hypersocket.quirkey.client;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.KeyAgreement;

import org.spongycastle.util.encoders.Base64;

import com.hypersocket.crypto.ByteArrayReader;
import com.hypersocket.crypto.ByteArrayWriter;
import com.hypersocket.crypto.ECCryptoProvider;
import com.hypersocket.crypto.ECCryptoProviderFactory;
import com.hypersocket.crypto.QuiRKEYException;
import com.hypersocket.crypto.QuiRKEYTransaction;

public class ClientRegistrationTransaction extends QuiRKEYTransaction {

	int registrationId;
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
	String transactionType;
	boolean passcode;
	Long passcodeLength;
	String mobileId;
	String mobileName;

	public ClientRegistrationTransaction(KeyPair clientKeyPair,
			String encodedRegistration, String curve) throws QuiRKEYException,
			IOException {

		this.clientKeyPair = clientKeyPair;
		this.ecProvider = ECCryptoProviderFactory.createInstance(curve);
		ByteArrayReader reader = new ByteArrayReader(
				Base64.decode(encodedRegistration));

		try {
			int id = reader.read();
			if (id != MSG_REGISTRATION_INFO) {
				if (id == MSG_AUTHENTICATION_FAILURE) {
					throw new QuiRKEYException((int) reader.readInt(),
							reader.readString());
				} else {
					throw new IOException("Unexpected message id " + id
							+ " received during registration");
				}
			}
			registrationId = (int) reader.readInt();
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
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchProviderException | InvalidAlgorithmParameterException
				| IllegalStateException | InvalidKeySpecException e) {
			throw new IOException(e);
		} finally {
			reader.close();
		}

	}

	public int getRegistrationId() {
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

	public String getTransactionType() {
		return transactionType;
	}

	public boolean isPasscode() {
		return passcode;
	}

	public void setPasscode(boolean passcode) {
		this.passcode = passcode;
	}

	public Long getPasscodeLength() {
		return passcodeLength;
	}

	public void setPasscodeLength(Long passcodeLength) {
		this.passcodeLength = passcodeLength;
	}

	public String generateRegistrationRequest(String mobileId, String mobileName)
			throws IOException {

		ByteArrayWriter writer = new ByteArrayWriter();

		this.mobileId = mobileId;
		this.mobileName = mobileName;

		try {
			writer.write(MSG_REGISTRATION_PROCESS);
			writer.writeInt(registrationId);
			writer.writeString(mobileId);
			writer.writeString(mobileName);
			writer.writeBinaryString(Q_S);
			writer.writeBinaryString(clientKeyPair.getPublic().getEncoded());

			return Base64.toBase64String(writer.toByteArray());
		} finally {
			writer.close();
		}
	}

	public String verifyRegistrationResponse(String encodedResponse)
			throws IOException, QuiRKEYException {

		ByteArrayReader reader = new ByteArrayReader(
				Base64.decode(encodedResponse));
		int messageId = reader.read();

		try {
			if (messageId != MSG_REGISTRATION_ACCEPT) {
				if (messageId == MSG_AUTHENTICATION_FAILURE) {
					throw new QuiRKEYException((int) reader.readInt(),
							reader.readString());
				} else {
					throw new IOException("Unexpected message id " + messageId
							+ " received during registration");
				}
			}

			username = reader.readString();
			serverPublicKey = reader.readBinaryString();
			passcode = reader.readBoolean();
			if (passcode) {
				passcodeLength = reader.readInt();
			}

			byte[] signature = reader.readBinaryString();

			PublicKey publicKey = ecProvider.decodePublicKey(serverPublicKey);

			clientExchangeHash = generateExchangeHash(Q_C, Q_S,
					serverPublicKey, clientKeyPair.getPublic().getEncoded(),
					username, mobileId, registrationId, secret, mobileName, url);

			if (!ecProvider.verify(publicKey, signature, clientExchangeHash)) {
				throw new IOException("Could not verify server signature");
			}

			ByteArrayWriter writer = new ByteArrayWriter();

			try {
				writer.write(MSG_REGISTRATION_CONFIRM);
				writer.writeInt(registrationId);
				writer.writeBinaryString(ecProvider.sign(
						clientKeyPair.getPrivate(), clientExchangeHash));

				return Base64.toBase64String(writer.toByteArray());
			} catch (Exception e) {
				throw new IOException(e);
			} finally {
				writer.close();
			}
		} catch (InvalidKeySpecException | NoSuchAlgorithmException
				| NoSuchProviderException | InvalidKeyException
				| SignatureException e1) {
			throw new IOException(e1);
		} finally {
			reader.close();
		}
	}
}

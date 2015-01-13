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
import java.security.SecureRandom;
import java.util.Date;
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
	byte[] Q_S;
	byte[] signature;
	byte[] clientKey;
	byte[] exchangeHash;
	String username;
	URL serverURL;
	KeyPair serverKey;
	int registrationId;
	PublicKey ec;
	PublicKey clientPublicKey;
	ECCryptoProvider ecProvider;
	String mobileId;
	String mobileName;
	Date creationDate;
	boolean passcode;
	int passcodeLength;
	BigInteger secret;
	boolean complete = false;

	public ServerRegistrationTransaction(String username, URL serverURL,
			KeyPair serverKey, String curve, boolean passcode, int passcodeLength)
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
		this.registrationId = new SecureRandom().nextInt();
		this.creationDate = new Date();
		this.passcode = passcode;
		this.passcodeLength = passcodeLength;

	}

	public String getMobileId() {
		return mobileId;
	}

	public String getMobileName() {
		return mobileName;
	}

	public int getRegistrationId() {
		return registrationId;
	}

	public Date getCreationDate() {
		return creationDate;
	}

	public String generateRegistrationInfo() throws IOException {
		ByteArrayWriter msg = new ByteArrayWriter();

		try {
			msg.write(MSG_REGISTRATION_INFO);
			msg.writeInt(registrationId);
//			msg.writeString(username);
			msg.writeString(serverURL.toExternalForm());
			msg.writeBinaryString(Q_C);

//			msg.writeBinaryString(serverKey.getPublic().getEncoded());
//			msg.writeBoolean(passcode);
//			if(passcode){
//				msg.writeInt(passcodeLength);
//			}

			String encoded = Base64.encodeBase64String(msg.toByteArray());
			System.out.println("Base64 data is " + encoded.length() + " characters");
			return encoded;
		} finally {
			msg.close();
		}
	}

	private void readData(String encodedResponse) throws IOException {

		ByteArrayReader reader = new ByteArrayReader(
				Base64.decodeBase64(encodedResponse));

		try {
			int id = reader.read();
			if(id != MSG_REGISTRATION_PROCESS) {
				throw new IOException("Unexpected message id " + id);
			}
			registrationId = (int)reader.readInt();
			mobileId = reader.readString();
			mobileName = reader.readString();
			Q_S = reader.readBinaryString();
			clientKey = reader.readBinaryString();
//			signature = reader.readBinaryString();

			clientPublicKey = ecProvider.decodePublicKey(clientKey);
		} catch (Exception e) {
			throw new IOException(e);
		} finally {
			reader.close();
		}
	}

	public byte[] getClientPublicKey() throws IOException {
		return clientKey;
	}

	public String processRequestionRequest(String encodedResponse)
			throws IOException {

		readData(encodedResponse);
		try {

			keyAgreement.doPhase(ecProvider.decodeKey(Q_S), true);

			byte[] tmp = keyAgreement.generateSecret();
			if ((tmp[0] & 0x80) == 0x80) {
				byte[] tmp2 = new byte[tmp.length + 1];
				System.arraycopy(tmp, 0, tmp2, 1, tmp.length);
				tmp = tmp2;
			}

			// Calculate diffe hellman k value
			secret = new BigInteger(tmp);

			exchangeHash = generateExchangeHash(Q_C, Q_S,
					serverKey.getPublic().getEncoded(), clientKey, username,
					mobileId, registrationId, secret, mobileName,
					serverURL.toExternalForm());
//
//			if (!ecProvider.verify(clientPublicKey, signature, exchangeHash)) {
//				throw new Exception("Invalid client signature");
//			}

			ByteArrayWriter writer = new ByteArrayWriter();

			ByteArrayWriter signatureResponse = new ByteArrayWriter();

			try {
				writer.write(MSG_REGISTRATION_ACCEPT);
				writer.writeString(username);
				writer.writeBinaryString(serverKey.getPublic().getEncoded());
				writer.writeBoolean(passcode);
				if(passcode){
					writer.writeInt(passcodeLength);
				}
				writer.writeBinaryString(ecProvider.sign(
						serverKey.getPrivate(), exchangeHash));
				complete = true;
				return Base64.encodeBase64String(writer.toByteArray());

			} finally {
				writer.close();
				signatureResponse.close();
			}

		} catch (Exception e) {
			throw new IOException(e);
		}
	}
	
	public boolean processRegistrationConfirmation(String encodedResponse) throws IOException {
		
		ByteArrayReader reader = new ByteArrayReader(
				Base64.decodeBase64(encodedResponse));

		try {
			int id = reader.read();
			if(id != MSG_REGISTRATION_CONFIRM) {
				throw new IOException("Unexpected message id " + id);
			}
			registrationId = (int)reader.readInt();
			signature = reader.readBinaryString();

			
			return ecProvider.verify(clientPublicKey, signature, exchangeHash);
			
		} catch (Exception e) {
			throw new IOException(e);
		} finally {
			reader.close();
		}
	}

	public String generateErrorMessage(int errorCode, String errorDesc) throws IOException {
		
		ByteArrayWriter msg = new ByteArrayWriter();

		try {
			msg.write(MSG_REGISTRATION_FAILURE);
			msg.writeInt(errorCode);
			msg.writeString(errorDesc);
			
			return Base64.encodeBase64String(msg.toByteArray());
		} finally {
			msg.close();
		}
	}

	public boolean isComplete() {
		return complete;
	}
}

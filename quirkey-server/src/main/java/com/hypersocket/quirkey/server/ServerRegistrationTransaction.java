package com.hypersocket.quirkey.server;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;

import javax.crypto.KeyAgreement;

import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.interfaces.ECPublicKey;
import org.spongycastle.jce.spec.ECNamedCurveParameterSpec;
import org.spongycastle.util.encoders.Base64;

import com.hypersocket.crypto.ByteArrayReader;
import com.hypersocket.crypto.ByteArrayWriter;
import com.hypersocket.crypto.ECDSAUtils;
import com.hypersocket.crypto.ECUtils;
import com.hypersocket.crypto.QuiRKEYTransaction;

public class ServerRegistrationTransaction extends QuiRKEYTransaction {

	KeyAgreement keyAgreement;
	byte[] Q_C;
	String username;
	URL serverURL;
	KeyPair serverKey;
	String registrationId;
	ECPublicKey ec;

	public ServerRegistrationTransaction(String username, URL serverURL, KeyPair serverKey)
			throws InvalidAlgorithmParameterException,
			NoSuchAlgorithmException, NoSuchProviderException,
			InvalidKeyException {

		this.username = username;
		this.serverURL = serverURL;
		this.serverKey = serverKey;

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDH", ECDSAUtils.getJCEProviderName());
		ECNamedCurveParameterSpec namedSpec = ECNamedCurveTable
				.getParameterSpec("secp256r1");
		keyGen.initialize(namedSpec, new SecureRandom());

		keyAgreement = KeyAgreement.getInstance("ECDH", ECDSAUtils.getJCEProviderName());
		KeyPair keyPair = keyGen.generateKeyPair();
		keyAgreement.init(keyPair.getPrivate());

		ec = (ECPublicKey) keyPair.getPublic();

		Q_C = ECUtils.toByteArray(ec.getQ(), namedSpec.getCurve());

		registrationId = UUID.randomUUID().toString();

	}

	public String generateRegistrationInfo() throws IOException {
		ByteArrayWriter msg = new ByteArrayWriter();

		try {
			msg.writeString(registrationId);
			msg.writeString(username);
			msg.writeString(serverURL.toExternalForm());
			msg.writeBinaryString(Q_C);
			msg.writeBinaryString(serverKey.getPublic().getEncoded());

			return Base64.toBase64String(msg.toByteArray());
		} finally {
			msg.close();
		}
	}

	public String verifyResponse(String encodedResponse) throws IOException {

		ByteArrayReader reader = new ByteArrayReader(
				Base64.decode(encodedResponse));

		try {

			String registrationId = reader.readString();
			String mobileId = reader.readString();
			String mobileName = reader.readString();
			byte[] Q_S = reader.readBinaryString();
			byte[] clientKey = reader.readBinaryString();

			byte[] signature = reader.readBinaryString();

			KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
			X509EncodedKeySpec spec = new X509EncodedKeySpec(clientKey);
			PublicKey clientPublicKey = keyFactory.generatePublic(spec);

			keyAgreement.doPhase(ECUtils.decodeKey(Q_S, "secp256r1"), true);

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

			if (!ECDSAUtils.verify(clientPublicKey, signature, exchangeHash)) {
				throw new Exception("Invalid client signature");
			}

			ByteArrayWriter writer = new ByteArrayWriter();

			ByteArrayWriter signatureResponse = new ByteArrayWriter();

			try {
				writer.writeBinaryString(ECDSAUtils.sign(
						serverKey.getPrivate(), exchangeHash));

				return Base64.toBase64String(writer.toByteArray());

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

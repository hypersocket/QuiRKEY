package com.hypersocket.quirkey.client;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
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

	public ClientRegistrationTransaction(KeyPair clientKeyPair,
			String encodedRegistration) throws IOException {

		this.clientKeyPair = clientKeyPair;

		ByteArrayReader reader = new ByteArrayReader(
				Base64.decode(encodedRegistration));

		try {
			registrationId = reader.readString();
			username = reader.readString();
			url = reader.readString();
			Q_C = reader.readBinaryString();
			serverPublicKey = reader.readBinaryString();

			KeyPairGenerator keyGen = KeyPairGenerator
					.getInstance("ECDH");
			ECNamedCurveParameterSpec namedSpec = ECNamedCurveTable
					.getParameterSpec("secp256r1");
			keyGen.initialize(namedSpec, new SecureRandom());

			KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
			KeyPair keyPair = keyGen.generateKeyPair();
			keyAgreement.init(keyPair.getPrivate());

			ECPublicKey ec = (ECPublicKey) keyPair.getPublic();
			Q_S = ECUtils.toByteArray(ec.getQ(), namedSpec.getCurve());

			keyAgreement.doPhase(ECUtils.decodeKey(Q_C, "secp256r1"), true);

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
		}

	}

	public String generateRegistrationRequest(String mobileName) throws IOException {
		
		ByteArrayWriter writer = new ByteArrayWriter();

		try {
			String mobileId = UUID.randomUUID().toString();

			writer.writeString(registrationId);
			writer.writeString(mobileId);
			writer.writeString(mobileName);
			writer.writeBinaryString(Q_S);
			writer.writeBinaryString(clientKeyPair.getPublic().getEncoded());

			clientExchangeHash = generateExchangeHash(Q_C, Q_S, serverPublicKey,
					clientKeyPair.getPublic().getEncoded(), username, mobileId,
					registrationId, secret, mobileName, url);

			writer.writeBinaryString(ECDSAUtils.sign(clientKeyPair.getPrivate(), clientExchangeHash));
			
			return Base64.toBase64String(writer.toByteArray());
		} catch (Exception e) {
			throw new IOException(e);
		}
	}

	public boolean verifyReqistrationResponse(String encodedResponse) throws IOException {

		ByteArrayReader reader = new ByteArrayReader(Base64.decode(encodedResponse));

		try {
			byte[] signature = reader.readBinaryString();

			KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
			X509EncodedKeySpec spec = new X509EncodedKeySpec(serverPublicKey);
			PublicKey serverPublicKey = keyFactory.generatePublic(spec);
			return ECDSAUtils.verify(serverPublicKey, signature, clientExchangeHash);
		} catch (Exception e) {
			throw new IOException(e);
		}
	}
}

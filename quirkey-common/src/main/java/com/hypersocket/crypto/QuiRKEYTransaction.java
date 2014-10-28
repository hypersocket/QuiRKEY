package com.hypersocket.crypto;

import java.math.BigInteger;

public class QuiRKEYTransaction {

	public byte[] generateExchangeHash(byte[] Q_C, byte[] Q_S,
			byte[] serverKey, byte[] clientKey, String username,
			String mobileId, String registrationId, BigInteger secret,
			String mobileName, String url) throws Exception {

		AbstractDigest hash = new AbstractDigest("SHA-1");

		hash.putInt(Q_C.length);
		hash.putBytes(Q_C);

		hash.putInt(Q_S.length);
		hash.putBytes(Q_S);

		hash.putInt(serverKey.length);
		hash.putBytes(serverKey);

		hash.putInt(clientKey.length);
		hash.putBytes(clientKey);

		hash.putInt(url.getBytes("UTF-8").length);
		hash.putBytes(url.getBytes("UTF-8"));

		hash.putInt(mobileId.getBytes("UTF-8").length);
		hash.putBytes(mobileId.getBytes("UTF-8"));

		hash.putInt(mobileName.getBytes("UTF-8").length);
		hash.putBytes(mobileName.getBytes("UTF-8"));

		hash.putInt(username.getBytes("UTF-8").length);
		hash.putBytes(username.getBytes("UTF-8"));

		hash.putInt(registrationId.getBytes("UTF-8").length);
		hash.putBytes(registrationId.getBytes("UTF-8"));

		hash.putBigInteger(secret);

		return hash.doFinal();
	}

}

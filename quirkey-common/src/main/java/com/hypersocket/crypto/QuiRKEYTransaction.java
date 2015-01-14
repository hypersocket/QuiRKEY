package com.hypersocket.crypto;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class QuiRKEYTransaction {

	public static final byte MSG_REGISTRATION_INFO = 1;
	public static final byte MSG_REGISTRATION_PROCESS = 2;
	public static final byte MSG_REGISTRATION_FAILURE = 3;
	public static final byte MSG_REGISTRATION_ACCEPT = 4;
	public static final byte MSG_REGISTRATION_CONFIRM = 5;
	
	public static final byte MSG_AUTHENTICATION_INFO = 10;
	public static final byte MSG_AUTHENTICATION_PROCESS = 11;
	public static final byte MSG_AUTHENTICATION_FAILURE = 12;
	public static final byte MSG_AUTHENTICATION_SUCCESS = 13;
	
	public byte[] generateExchangeHash(byte[] Q_C, byte[] Q_S,
			byte[] serverKey, byte[] clientKey, String username,
			String mobileId, int registrationId, BigInteger secret,
			String mobileName, String url) throws UnsupportedEncodingException,
			NoSuchAlgorithmException, NoSuchProviderException  {

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

		hash.putInt(registrationId);

		hash.putBigInteger(secret);

		return hash.doFinal();
	}

}

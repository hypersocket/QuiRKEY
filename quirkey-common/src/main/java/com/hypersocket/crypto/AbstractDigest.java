package com.hypersocket.crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * An abstract class that implements the {@link com.maverick.ssh.components.Digest}
 * interface to provide support for JCE based digests.
 * @author Lee David Painter
 *
 */
public class AbstractDigest {

	MessageDigest digest;
	String jceAlgorithm;
	
	public AbstractDigest(String jceAlgorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
		digest = MessageDigest.getInstance(jceAlgorithm);
	}
	
	public byte[] doFinal() {
		return digest.digest();
	}

	public void putBigInteger(BigInteger bi) {
		
	    byte[] data = bi.toByteArray();
	    putInt(data.length);
	    putBytes(data);
	}

	public void putByte(byte b) {
		digest.update(b);
	}

	public void putBytes(byte[] data) {
		digest.update(data, 0, data.length);
	}

	public void putBytes(byte[] data, int offset, int len) {
		digest.update(data, offset, len);
	}

	public void putInt(int i) {
		putBytes(ByteArrayWriter.encodeInt(i));
	}

	public void putString(String str) {
	    putInt(str.length());
	    putBytes(str.getBytes());
	}

	public void reset() {
		digest.reset();
	}
	
	public String getProvider() {
		return digest.getProvider().getName();
	}

}

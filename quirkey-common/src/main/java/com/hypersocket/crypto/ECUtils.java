package com.hypersocket.crypto;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;

import org.spongycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.ECPointUtil;
import org.spongycastle.jce.interfaces.ECPublicKey;
import org.spongycastle.jce.spec.ECNamedCurveParameterSpec;
import org.spongycastle.math.ec.ECCurve;

public class ECUtils {

	public static byte[] toByteArray(ECPoint e, EllipticCurve curve) {
		byte[] x = e.getAffineX().toByteArray();
		byte[] y = e.getAffineY().toByteArray();
		int i, xoff = 0, yoff = 0;
		for (i = 0; i < x.length - 1; i++)
			if (x[i] != 0) {
				xoff = i;
				break;
			}
		for (i = 0; i < y.length - 1; i++)
			if (y[i] != 0) {
				yoff = i;
				break;
			}
		int len = (curve.getField().getFieldSize() + 7) / 8;
		if ((x.length - xoff) > len || (y.length - yoff) > len)
			return null;
		byte[] ret = new byte[len * 2 + 1];
		ret[0] = 4;
		System.arraycopy(x, xoff, ret, 1 + len - (x.length - xoff), x.length
				- xoff);
		System.arraycopy(y, yoff, ret, ret.length - (y.length - yoff), y.length
				- yoff);
		return ret;
	}

	public static ECPoint fromByteArray(byte[] b, EllipticCurve curve) {
		int len = (curve.getField().getFieldSize() + 7) / 8;
		if (b.length != 2 * len + 1 || b[0] != 4)
			return null;
		byte[] x = new byte[len];
		byte[] y = new byte[len];
		System.arraycopy(b, 1, x, 0, len);
		System.arraycopy(b, len + 1, y, 0, len);
		return new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
	}


	public static ECPublicKey decodeKey(byte[] encoded, String namedCurve) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException{
	    ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec(namedCurve);
	    KeyFactory fact = KeyFactory.getInstance("ECDSA", "SC");
	    ECCurve curve = params.getCurve();
	    java.security.spec.EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, params.getSeed());
	    java.security.spec.ECPoint point=ECPointUtil.decodePoint(ellipticCurve, encoded);
	    java.security.spec.ECParameterSpec params2=EC5Util.convertSpec(ellipticCurve, params);
	    java.security.spec.ECPublicKeySpec keySpec = new java.security.spec.ECPublicKeySpec(point,params2);
	    return (ECPublicKey) fact.generatePublic(keySpec);
	}
	
	public static byte[] toByteArray(org.spongycastle.math.ec.ECPoint e,
			ECCurve curve) {
		byte[] x = e.getAffineXCoord().getEncoded();
		byte[] y = e.getAffineYCoord().getEncoded();
		int i, xoff = 0, yoff = 0;
		for (i = 0; i < x.length - 1; i++)
			if (x[i] != 0) {
				xoff = i;
				break;
			}
		for (i = 0; i < y.length - 1; i++)
			if (y[i] != 0) {
				yoff = i;
				break;
			}
		int len = (curve.getFieldSize() + 7) / 8;
		if ((x.length - xoff) > len || (y.length - yoff) > len)
			return null;
		byte[] ret = new byte[len * 2 + 1];
		ret[0] = 4;
		System.arraycopy(x, xoff, ret, 1 + len - (x.length - xoff), x.length
				- xoff);
		System.arraycopy(y, yoff, ret, ret.length - (y.length - yoff), y.length
				- yoff);
		return ret;
	}
}

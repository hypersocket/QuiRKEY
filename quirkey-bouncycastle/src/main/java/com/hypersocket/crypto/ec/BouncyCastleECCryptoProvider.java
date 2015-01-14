package com.hypersocket.crypto.ec;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;

import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import com.hypersocket.crypto.ECCryptoProvider;

public class BouncyCastleECCryptoProvider implements ECCryptoProvider {

	ECNamedCurveParameterSpec namedSpec;
	String namedCurve;

	public BouncyCastleECCryptoProvider() {
	}

	public void init(String curve) {
		namedSpec = ECNamedCurveTable.getParameterSpec(curve);
		namedCurve = curve;
	}

	@Override
	public KeyPair generateKeyPair() throws NoSuchAlgorithmException,
			NoSuchProviderException, InvalidAlgorithmParameterException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDH", "BC");
		keyGen.initialize(namedSpec, new SecureRandom());
		KeyPair keyPair = keyGen.generateKeyPair();
		return keyPair;
	}

	@Override
	public KeyAgreement createKeyAgreement(KeyPair keyPair)
			throws NoSuchAlgorithmException, NoSuchProviderException,
			InvalidAlgorithmParameterException, InvalidKeyException {

		KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
		keyAgreement.init(keyPair.getPrivate());
		return keyAgreement;
	}

	@Override
	public byte[] generateQ(PublicKey ec) {
		ECPublicKey ecKey = (ECPublicKey) ec;

		return toByteArray(ecKey.getQ(), namedSpec.getCurve());
	}

	@Override
	public PublicKey decodePublicKey(byte[] publicKey)
			throws InvalidKeySpecException, NoSuchAlgorithmException,
			NoSuchProviderException {
		KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
		X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKey);
		return keyFactory.generatePublic(spec);
	}

	@Override
	public PublicKey decodeKey(byte[] encoded) throws InvalidKeySpecException,
			NoSuchAlgorithmException, NoSuchProviderException {

		ECNamedCurveParameterSpec params = ECNamedCurveTable
				.getParameterSpec(namedCurve);
		KeyFactory fact = KeyFactory.getInstance("ECDSA", "BC");
		ECCurve curve = params.getCurve();
		java.security.spec.EllipticCurve ellipticCurve = EC5Util.convertCurve(
				curve, params.getSeed());
		java.security.spec.ECPoint point = ECPointUtil.decodePoint(
				ellipticCurve, encoded);
		java.security.spec.ECParameterSpec params2 = EC5Util.convertSpec(
				ellipticCurve, params);
		java.security.spec.ECPublicKeySpec keySpec = new java.security.spec.ECPublicKeySpec(
				point, params2);
		return fact.generatePublic(keySpec);
	}

	@Override
	public byte[] sign(PrivateKey key, byte[] data) throws IOException,
			NoSuchAlgorithmException, NoSuchProviderException,
			SignatureException, InvalidKeyException {

		Signature sig = Signature.getInstance("SHA256/ECDSA", "BC");
		sig.initSign(key);
		sig.update(data);
		return sig.sign();
	}

	@Override
	public boolean verify(PublicKey key, byte[] signature, byte[] data)
			throws IOException, NoSuchAlgorithmException,
			NoSuchProviderException, SignatureException, InvalidKeyException {

		Signature sig = Signature.getInstance("SHA256/ECDSA", "BC");
		sig.initVerify(key);
		sig.update(data);
		return sig.verify(signature);
	}

//	private byte[] toByteArray(ECPoint e, EllipticCurve curve) {
//		byte[] x = e.getAffineX().toByteArray();
//		byte[] y = e.getAffineY().toByteArray();
//		int i, xoff = 0, yoff = 0;
//		for (i = 0; i < x.length - 1; i++)
//			if (x[i] != 0) {
//				xoff = i;
//				break;
//			}
//		for (i = 0; i < y.length - 1; i++)
//			if (y[i] != 0) {
//				yoff = i;
//				break;
//			}
//		int len = (curve.getField().getFieldSize() + 7) / 8;
//		if ((x.length - xoff) > len || (y.length - yoff) > len)
//			return null;
//		byte[] ret = new byte[len * 2 + 1];
//		ret[0] = 4;
//		System.arraycopy(x, xoff, ret, 1 + len - (x.length - xoff), x.length
//				- xoff);
//		System.arraycopy(y, yoff, ret, ret.length - (y.length - yoff), y.length
//				- yoff);
//		return ret;
//	}

//	private ECPoint fromByteArray(byte[] b, EllipticCurve curve) {
//		int len = (curve.getField().getFieldSize() + 7) / 8;
//		if (b.length != 2 * len + 1 || b[0] != 4)
//			return null;
//		byte[] x = new byte[len];
//		byte[] y = new byte[len];
//		System.arraycopy(b, 1, x, 0, len);
//		System.arraycopy(b, len + 1, y, 0, len);
//		return new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
//	}

	private byte[] toByteArray(org.bouncycastle.math.ec.ECPoint e, ECCurve curve) {
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

	@Override
	public KeyPair loadKeyPair(File keyfile) throws IOException {
		
		InputStream in = new FileInputStream(keyfile);
		Reader r = new InputStreamReader(in);
		PEMParser parser = new PEMParser(r);

		try {
			Object obj = parser.readObject();
			if (obj == null) {
				throw new IOException("Invalid key file");
			}

			if (obj instanceof PEMKeyPair) {
				obj = new JcaPEMKeyConverter().setProvider("BC").getKeyPair(
						(PEMKeyPair) obj);
			}

			if (obj instanceof KeyPair) {
				return (KeyPair) obj;
			}

			throw new IOException("Unexpected object returned from file "
					+ obj.getClass().getName());
		} finally {
			in.close();
			r.close();
			parser.close();
		}
	}
	
	@Override
	public void saveKeyPair(KeyPair pair, File keyfile)
			throws IOException {
		
		OutputStream out = new FileOutputStream(keyfile);
		PEMWriter pem = new PEMWriter(new OutputStreamWriter(out));

		try {
			pem.writeObject(pair);
			pem.flush();
		} finally {
			out.close();
			pem.close();
		}
	}
}

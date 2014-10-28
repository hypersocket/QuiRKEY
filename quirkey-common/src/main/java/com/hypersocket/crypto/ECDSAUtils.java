package com.hypersocket.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;

import org.spongycastle.openssl.PEMKeyPair;
import org.spongycastle.openssl.PEMParser;
import org.spongycastle.openssl.PEMWriter;
import org.spongycastle.openssl.jcajce.JcaPEMKeyConverter;

public class ECDSAUtils {

	static {
		Security.insertProviderAt(
				new org.spongycastle.jce.provider.BouncyCastleProvider(), 0);
	}

	public static KeyPair generateKeyPair(String curve)
			throws InvalidAlgorithmParameterException,
			NoSuchAlgorithmException, NoSuchProviderException {

		ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(curve);

		KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "SC");

		g.initialize(ecGenSpec, new SecureRandom());

		KeyPair pair = g.generateKeyPair();

		return pair;
	}

	public static KeyPair loadKeyPair(File keyfile) throws IOException {

		InputStream in = new FileInputStream(keyfile);
		Reader r = new InputStreamReader(in);
		PEMParser parser = new PEMParser(r);

		try {
			Object obj = parser.readObject();
			if (obj == null) {
				throw new IOException("Invalid key file");
			}

			if (obj instanceof PEMKeyPair) {
				obj = new JcaPEMKeyConverter().setProvider("SC").getKeyPair(
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

	public static void saveKeyPair(KeyPair pair, File keyfile)
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

	public static byte[] sign(PrivateKey key, byte[] data) throws IOException,
			NoSuchAlgorithmException, NoSuchProviderException,
			SignatureException, InvalidKeyException {
		Signature sig = Signature.getInstance("SHA256/ECDSA", "SC");
		sig.initSign(key);
		sig.update(data);
		return sig.sign();
	}

	public static boolean verify(PublicKey key, byte[] signature, byte[] data) throws IOException,
			NoSuchAlgorithmException, NoSuchProviderException,
			SignatureException, InvalidKeyException {
		Signature sig = Signature.getInstance("SHA256/ECDSA", "SC");
		sig.initVerify(key);
		sig.update(data);
		return sig.verify(signature);
	}

	public static void main(String args[]) {

		try {
			File file = new File("test.key");
			saveKeyPair(generateKeyPair("secp256r1"), file);
			loadKeyPair(file);
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}

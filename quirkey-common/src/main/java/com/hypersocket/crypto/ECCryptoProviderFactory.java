package com.hypersocket.crypto;

public class ECCryptoProviderFactory {

	static ECCryptoProvider provider;

	@SuppressWarnings("unchecked")
	public static ECCryptoProvider createInstance(String curve) {
		
		Class<ECCryptoProvider> clz = null;
		try {
			clz = (Class<ECCryptoProvider>) Class.forName("com.hypersocket.crypto.ec.SpongyCastleECCryptoProvider");
		} catch (ClassNotFoundException e) {
			try {
				clz = (Class<ECCryptoProvider>) Class.forName("com.hypersocket.crypto.ec.BouncyCastleECCryptoProvider");
			} catch (ClassNotFoundException e1) {
				throw new IllegalStateException("Unable to locate either the SpongyCastle or BouncyCastle ECCryptoProvider implementation");
			}
		}
		
		ECCryptoProvider provider;
		try {
			provider = clz.newInstance();
			provider.init(curve);
			return provider;
		} catch (Throwable e) {
			throw new IllegalStateException("Unable to create ECCryptoProvider implementation", e);
		}
		
	}
}

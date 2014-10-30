package com.hypersocket.quirkey.tests;

import java.net.URL;
import java.security.KeyPair;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.hypersocket.crypto.ECCryptoProvider;
import com.hypersocket.crypto.ECCryptoProviderFactory;
import com.hypersocket.quirkey.client.ClientRegistrationTransaction;
import com.hypersocket.quirkey.server.ServerRegistrationTransaction;

public class TestClientServerInteraction {

	@BeforeClass
	public static void setupJCEProvider() {
		Security.insertProviderAt(new BouncyCastleProvider(), 0);
	}
	
	@Test
	public void testClientServer() throws Exception {
		
		ECCryptoProvider provider = ECCryptoProviderFactory.createInstance("secp256r1");
		
		KeyPair serverKey = provider.generateKeyPair();
		KeyPair clientKey = provider.generateKeyPair();
		
		ServerRegistrationTransaction server = new ServerRegistrationTransaction("lee", 
				new URL("http://localhost"), serverKey, "secp256r1");
		
		String registrationInfo = server.generateRegistrationInfo();
		
		ClientRegistrationTransaction client = new ClientRegistrationTransaction(clientKey, 
				registrationInfo, "secp256r1");
		
		String clientRequest = client.generateRegistrationRequest("Lee's Mobile");
		String serverResponse = server.verifyResponse(clientRequest);
		Assert.assertTrue(client.verifyReqistrationResponse(serverResponse));
	}
}

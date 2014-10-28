package com.hypersocket.quirkey.tests;

import java.net.URL;
import java.security.KeyPair;

import org.junit.Assert;
import org.junit.Test;

import com.hypersocket.crypto.ECDSAUtils;
import com.hypersocket.quirkey.client.ClientRegistrationTransaction;
import com.hypersocket.quirkey.server.ServerRegistrationTransaction;

public class TestClientServerInteraction {

	@Test
	public void testClientServer() throws Exception {
		
		KeyPair serverKey = ECDSAUtils.generateKeyPair("secp256r1");
		KeyPair clientKey = ECDSAUtils.generateKeyPair("secp256r1");
		
		ServerRegistrationTransaction server = new ServerRegistrationTransaction("lee", 
				new URL("http://localhost"), serverKey);
		
		String registrationInfo = server.generateRegistrationInfo();
		
		ClientRegistrationTransaction client = new ClientRegistrationTransaction(clientKey, 
				registrationInfo);
		
		String clientRequest = client.generateRegistrationRequest("Lee's Mobile");
		String serverResponse = server.verifyResponse(clientRequest);
		Assert.assertTrue(client.verifyReqistrationResponse(serverResponse));
	}
}

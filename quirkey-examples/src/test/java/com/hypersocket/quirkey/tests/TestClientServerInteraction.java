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
import com.hypersocket.quirkey.client.ClientAuthenticationTransaction;
import com.hypersocket.quirkey.client.ClientRegistrationTransaction;
import com.hypersocket.quirkey.server.ServerAuthenticationTransaction;
import com.hypersocket.quirkey.server.ServerRegistrationTransaction;

public class TestClientServerInteraction {

	private static final String ID = "Mobile ID";
	private static final String MOBILE_NAME = "Lee's Mobile";
	private static final String USER_NAME = "Lee";

	@BeforeClass
	public static void setupJCEProvider() {
		Security.insertProviderAt(new BouncyCastleProvider(), 0);
	}

	@Test
	public void testClientServerRegistration() throws Exception {

		ECCryptoProvider provider = ECCryptoProviderFactory
				.createInstance("secp256r1");

		KeyPair serverKey = provider.generateKeyPair();
		KeyPair clientKey = provider.generateKeyPair();

		ServerRegistrationTransaction server = new ServerRegistrationTransaction(
				USER_NAME, new URL("http://localhost"), serverKey, "secp256r1");

		String registrationInfo = server.generateRegistrationInfo();

		ClientRegistrationTransaction client = new ClientRegistrationTransaction(
				clientKey, registrationInfo, "secp256r1");

		String clientRequest = client.generateRegistrationRequest(ID,
				MOBILE_NAME);
		String serverResponse = server.verifyResponse(clientRequest);
		Assert.assertTrue(client.verifyRegistrationResponse(serverResponse));
	}

	@Test
	public void testClientServerAuthentication() throws Exception {

		ECCryptoProvider provider = ECCryptoProviderFactory
				.createInstance("secp256r1");

		KeyPair serverKey = provider.generateKeyPair();
		KeyPair clientKey = provider.generateKeyPair();

		ServerRegistrationTransaction registrationServer = new ServerRegistrationTransaction(
				USER_NAME, new URL("http://localhost"), serverKey, "secp256r1");

		String registrationInfo = registrationServer.generateRegistrationInfo();

		ClientRegistrationTransaction registrationClient = new ClientRegistrationTransaction(
				clientKey, registrationInfo, "secp256r1");

		String registrationClientRequest = registrationClient
				.generateRegistrationRequest(ID, MOBILE_NAME);
		String registrationServerResponse = registrationServer
				.verifyResponse(registrationClientRequest);
		if (registrationClient
				.verifyRegistrationResponse(registrationServerResponse)) {
			ServerAuthenticationTransaction authenticationServer = new ServerAuthenticationTransaction(
					new URL("http://localhost"), serverKey, "secp256r1");

			String authenticationInfo = authenticationServer
					.generateAuthenticationInfo();

			ClientAuthenticationTransaction authenticationClient = new ClientAuthenticationTransaction(
					clientKey, authenticationInfo, "secp256r1");

			String authenticationClientRequest = authenticationClient
					.generateAuthenticationRequest(ID, MOBILE_NAME,
							registrationClient.getServerPublicKey(),
							registrationClient.getUsername());

			Assert.assertTrue(authenticationServer.verifyResponse(
					authenticationClientRequest, serverKey,
					registrationClient.getUsername()));
		}
	}
}
